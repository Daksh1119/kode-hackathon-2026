# """
# Subdomain Enumeration using crt.sh
# Usage: python subdomain_enum.py <domain>
# """

# import json
# import logging
# import sys
# from urllib.request import urlopen, Request
# from urllib.error import URLError, HTTPError
# import socket

# # ── Logging setup ─────────────────────────────────────────────────────────────
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     datefmt="%H:%M:%S",
# )
# log = logging.getLogger("subdomain_enum")

# # ── Constants ─────────────────────────────────────────────────────────────────
# CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
# TIMEOUT = 15  # seconds


# # ── Core Functions ─────────────────────────────────────────────────────────────

# def fetch_crtsh(domain: str) -> list[dict]:
#     """Fetch raw certificate records from crt.sh for the given domain."""
#     url = CRT_SH_URL.format(domain=domain)
#     log.info(f"Fetching data from: {url}")

#     req = Request(url, headers={"User-Agent": "subdomain-enum/1.0"})

#     try:
#         with urlopen(req, timeout=TIMEOUT) as response:
#             raw = response.read().decode("utf-8")
#     except socket.timeout:
#         raise TimeoutError(f"Request timed out after {TIMEOUT}s")
#     except HTTPError as e:
#         raise RuntimeError(f"HTTP error {e.code}: {e.reason}")
#     except URLError as e:
#         raise RuntimeError(f"Network error: {e.reason}")

#     if not raw.strip():
#         raise ValueError("Empty response from crt.sh")

#     try:
#         return json.loads(raw)
#     except json.JSONDecodeError as e:
#         raise ValueError(f"Failed to parse JSON response: {e}")


# def extract_subdomains(records: list[dict], root_domain: str) -> list[str]:
#     """
#     Parse certificate records and return a clean, deduplicated list
#     of subdomains belonging to root_domain.
#     """
#     seen: set[str] = set()

#     for record in records:
#         name_value = record.get("name_value", "")

#         # One record may contain multiple domains separated by newlines
#         for entry in name_value.split("\n"):
#             subdomain = entry.strip().lower()

#             # Skip wildcards
#             if subdomain.startswith("*"):
#                 log.debug(f"Skipping wildcard: {subdomain}")
#                 continue

#             # Keep only valid subdomains of the root domain
#             if subdomain.endswith(f".{root_domain}") or subdomain == root_domain:
#                 seen.add(subdomain)

#     return sorted(seen)


# def enumerate_subdomains(domain: str) -> list[str]:
#     """
#     Main entry point: fetch + parse + clean subdomains for a given domain.
#     Returns a sorted list of unique subdomains.
#     """
#     domain = domain.strip().lower()
#     log.info(f"Starting subdomain enumeration for: {domain}")

#     records = fetch_crtsh(domain)
#     log.info(f"Received {len(records)} certificate record(s)")

#     subdomains = extract_subdomains(records, domain)
#     log.info(f"Found {len(subdomains)} unique subdomain(s)")

#     return subdomains


# # ── CLI Entry Point ────────────────────────────────────────────────────────────

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python subdomain_enum.py <domain>")
#         print("Example: python subdomain_enum.py example.com")
#         sys.exit(1)

#     target = sys.argv[1]

#     try:
#         results = enumerate_subdomains(target)

#         print("\n── Results ──────────────────────────────")
#         if results:
#             for sub in results:
#                 print(f"  {sub}")
#             print(f"\nTotal: {len(results)} subdomain(s) found")
#         else:
#             print("  No subdomains found.")

#     except (TimeoutError, RuntimeError, ValueError) as e:
#         log.error(str(e))
#         sys.exit(1)















"""
Multi-Source Subdomain Enumeration
Sources (in priority order):
  1. AlienVault OTX   - Most reliable, rich structured JSON
  2. URLScan.io       - Good independent coverage
  3. HackerTarget     - Simple plain-text fallback

Usage: python subdomain_enum.py <domain>
"""

import json
import logging
import sys
import socket
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("subdomain_enum")

# ── Config ────────────────────────────────────────────────────────────────────
TIMEOUT     = 15
MAX_RETRIES = 3
RETRY_CODES = {502, 503, 504}

SOURCES = {
    "AlienVault OTX": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "URLScan.io"    : "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
    "HackerTarget"  : "https://api.hackertarget.com/hostsearch/?q={domain}",
}

PRIORITY = ["AlienVault OTX", "URLScan.io", "HackerTarget"]


# ── HTTP Helper ───────────────────────────────────────────────────────────────

def http_get(url: str, source: str) -> str:
    """Fetch a URL with retries on transient errors. Returns raw response text."""
    req = Request(url, headers={"User-Agent": "subdomain-enum/1.0"})

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read().decode("utf-8")

        except socket.timeout:
            err = f"Timed out after {TIMEOUT}s"
        except HTTPError as e:
            if e.code in RETRY_CODES:
                err = f"HTTP {e.code} {e.reason}"
            else:
                raise RuntimeError(f"[{source}] HTTP {e.code}: {e.reason}")
        except URLError as e:
            err = f"Network error: {e.reason}"

        if attempt < MAX_RETRIES:
            wait = 2 ** (attempt - 1)
            log.warning(f"[{source}] Attempt {attempt}/{MAX_RETRIES} failed ({err}). Retrying in {wait}s...")
            time.sleep(wait)
        else:
            raise RuntimeError(f"[{source}] All {MAX_RETRIES} attempts failed. Last: {err}")


# ── Per-Source Parsers ────────────────────────────────────────────────────────

def fetch_alienvault(domain: str) -> set[str]:
    """
    AlienVault OTX — JSON response.
    Extracts 'hostname' from each passive DNS record.
    """
    url = SOURCES["AlienVault OTX"].format(domain=domain)
    raw = http_get(url, "AlienVault OTX")
    data = json.loads(raw)

    found = set()
    for record in data.get("passive_dns", []):
        hostname = record.get("hostname", "").strip().lower()
        if hostname.endswith(f".{domain}") or hostname == domain:
            found.add(hostname)
    return found


def fetch_urlscan(domain: str) -> set[str]:
    """
    URLScan.io — JSON response.
    Extracts page domains and subdomains from scan results.
    """
    url = SOURCES["URLScan.io"].format(domain=domain)
    raw = http_get(url, "URLScan.io")
    data = json.loads(raw)

    found = set()
    for result in data.get("results", []):
        for field in ["page", "task"]:
            section = result.get(field, {})
            for key in ["domain", "apexDomain"]:
                val = section.get(key, "").strip().lower()
                if val.endswith(f".{domain}") or val == domain:
                    found.add(val)
    return found


def fetch_hackertarget(domain: str) -> set[str]:
    """
    HackerTarget — plain text response, one 'subdomain,ip' per line.
    """
    url = SOURCES["HackerTarget"].format(domain=domain)
    raw = http_get(url, "HackerTarget")

    if "error" in raw.lower() or "API count" in raw:
        raise RuntimeError(f"[HackerTarget] API limit hit: {raw.strip()}")

    found = set()
    for line in raw.splitlines():
        parts = line.split(",")
        if parts:
            subdomain = parts[0].strip().lower()
            if subdomain.endswith(f".{domain}") or subdomain == domain:
                found.add(subdomain)
    return found


# ── Source Registry ───────────────────────────────────────────────────────────

FETCHERS = {
    "AlienVault OTX": fetch_alienvault,
    "URLScan.io"    : fetch_urlscan,
    "HackerTarget"  : fetch_hackertarget,
}


# ── Parallel Aggregator ───────────────────────────────────────────────────────

def enumerate_subdomains(domain: str) -> dict:
    """
    Query all sources in parallel.
    Returns a dict with per-source results and merged unique subdomains.
    """
    domain = domain.strip().lower()
    log.info(f"Starting multi-source enumeration for: {domain}")
    log.info(f"Querying {len(FETCHERS)} sources in parallel...\n")

    per_source: dict[str, set[str]] = {}
    errors:     dict[str, str]      = {}

    def run(name: str) -> tuple[str, set[str]]:
        log.info(f"[{name}] Fetching...")
        result = FETCHERS[name](domain)
        log.info(f"[{name}] Found {len(result)} subdomain(s)")
        return name, result

    with ThreadPoolExecutor(max_workers=len(FETCHERS)) as pool:
        futures = {pool.submit(run, name): name for name in PRIORITY}
        for future in as_completed(futures):
            name = futures[future]
            try:
                src, results = future.result()
                per_source[src] = results
            except Exception as e:
                log.error(str(e))
                errors[name] = str(e)
                per_source[name] = set()

    # Merge all results
    merged = sorted(set().union(*per_source.values()))

    return {
        "domain"    : domain,
        "merged"    : merged,
        "per_source": per_source,
        "errors"    : errors,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python subdomain_enum.py <domain>")
        print("Example: python subdomain_enum.py example.com")
        sys.exit(1)

    target = sys.argv[1]

    try:
        report = enumerate_subdomains(target)

        # Per-source breakdown
        print("\n── Per-Source Results " + "─" * 38)
        for name in PRIORITY:
            subs   = report["per_source"].get(name, set())
            status = f"✗ FAILED — {report['errors'][name]}" if name in report["errors"] else f"✔ {len(subs)} found"
            print(f"\n  [{name}] {status}")
            for s in sorted(subs):
                print(f"    {s}")

        # Merged results
        print("\n── Merged Unique Subdomains " + "─" * 32)
        merged = report["merged"]
        if merged:
            for sub in merged:
                print(f"  {sub}")
            print(f"\nTotal: {len(merged)} unique subdomain(s) across all sources")
        else:
            print("  No subdomains found.")

    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)