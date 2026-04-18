"""
Security Findings → Layman Explanation (via Ollama)
Converts technical security scan JSON into plain English using a local Ollama model.

Requirements:
  - Ollama running locally: https://ollama.com
  - A pulled model e.g.: ollama pull llama3

Usage:
  python explain_findings.py findings.json
  python explain_findings.py findings.json --model mistral
  python explain_findings.py findings.json --model llama3 --host http://localhost:11434
"""

import json
import sys
import logging
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("explain_findings")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_MODEL   = "llama3"
DEFAULT_HOST    = "http://localhost:11434"
OLLAMA_ENDPOINT = "/api/generate"


# ── Prompt Builder ────────────────────────────────────────────────────────────

def build_prompt(findings_json: str) -> str:
    return f"""You are a cybersecurity assistant helping a non-technical business owner (like a CTO of a small company).

Your job is to explain technical security scan results in simple, clear, and actionable language.

Instructions:
- Do NOT use technical jargon
- Explain things like you are talking to a beginner
- Focus on:
  1. What was found
  2. Why it could be risky
  3. What should be done next
- Keep it short, clear, and practical
- Do NOT mention HTTP codes, JSON, or technical terms unless absolutely necessary

Format your response EXACTLY like this:

Summary:
(A simple 2-3 line overview of overall security posture)

Top Risks:
- (List key issues in simple terms)

What You Should Do:
- (Clear action steps, non-technical)

Scan Results:
{findings_json}"""


# ── Ollama API Call ───────────────────────────────────────────────────────────

def call_ollama(prompt: str, model: str, host: str) -> str:
    """Send prompt to local Ollama instance and return the full response text."""
    url     = host.rstrip("/") + OLLAMA_ENDPOINT
    payload = json.dumps({
        "model" : model,
        "prompt": prompt,
        "stream": False       # get full response at once
    }).encode("utf-8")

    req = Request(
        url,
        data    = payload,
        headers = {"Content-Type": "application/json"},
        method  = "POST"
    )

    log.info(f"Sending request to Ollama ({host}) using model '{model}'...")

    try:
        with urlopen(req, timeout=120) as resp:          # LLMs can be slow locally
            raw = resp.read().decode("utf-8")
    except HTTPError as e:
        raise RuntimeError(f"Ollama HTTP error {e.code}: {e.reason}")
    except URLError as e:
        raise RuntimeError(
            f"Cannot reach Ollama at {host}.\n"
            f"  → Is Ollama running? Start it with: ollama serve\n"
            f"  → Error: {e.reason}"
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError(f"Unexpected response from Ollama: {raw[:200]}")

    response_text = data.get("response", "").strip()
    if not response_text:
        raise ValueError("Ollama returned an empty response.")

    return response_text


# ── File Loader ───────────────────────────────────────────────────────────────

def load_findings(path: str) -> str:
    """Load and validate findings JSON from file. Returns pretty-printed JSON string."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"[ERROR] File not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"[ERROR] Invalid JSON in {path}: {e}")

    if isinstance(data, dict):
        data = [data]   # wrap single finding in a list

    log.info(f"Loaded {len(data)} finding(s) from '{path}'")
    return json.dumps(data, indent=2)


# ── Pretty Printer ────────────────────────────────────────────────────────────

def print_report(explanation: str, findings_count: int) -> None:
    width = 60
    print("\n" + "═" * width)
    print(f"  SECURITY REPORT  ({findings_count} finding(s) analyzed)")
    print("═" * width)
    print(explanation)
    print("═" * width + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert security findings JSON to plain-English using Ollama."
    )
    parser.add_argument(
        "findings_file",
        help="Path to findings JSON file (e.g. findings.json)"
    )
    parser.add_argument(
        "--model", "-m",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL})"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Ollama host URL (default: {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--save", "-s",
        metavar="OUTPUT_FILE",
        help="Optionally save the explanation to a text file"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # 1. Load findings
    findings_json   = load_findings(args.findings_file)
    findings_count  = len(json.loads(findings_json))

    # 2. Build prompt
    prompt = build_prompt(findings_json)

    # 3. Call Ollama
    try:
        explanation = call_ollama(prompt, model=args.model, host=args.host)
    except (RuntimeError, ValueError) as e:
        log.error(str(e))
        sys.exit(1)

    log.info("Explanation generated successfully.")

    # 4. Print report
    print_report(explanation, findings_count)

    # 5. Optionally save to file
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(explanation)
        log.info(f"Explanation saved to '{args.save}'")


if __name__ == "__main__":
    main()