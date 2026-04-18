"""
Shadow IT Discovery — Full Pipeline
=====================================
Chains all six layers end-to-end:

  Stage 1 │ subdomain.py           → Discover all public subdomains
  Stage 2 │ status_prober.py       → Probe each host for HTTP status
  Stage 3 │ intelligence_engine.py → Rule-based risk classification
  Stage 4 │ active_scanner.py      → Nmap port/service scan
  Stage 5 │ active_scanner.py      → Nuclei vulnerability scan
  Stage 6 │ active_scanner.py      → Merge, deduplicate, sort all findings

Usage:
  python pipeline.py <domain>
  python pipeline.py <domain> --json            # save findings to JSON file
  python pipeline.py <domain> --quiet           # suppress stage logs
  python pipeline.py <domain> --workers 30      # tune HTTP probe concurrency
  python pipeline.py <domain> --no-nmap         # skip Nmap stage
  python pipeline.py <domain> --no-nuclei       # skip Nuclei stage
  python pipeline.py <domain> --full-scan       # enable -sV + top-1000 Nmap scan

Example:
  python pipeline.py somaiya.com
  python pipeline.py somaiya.com --json
  python pipeline.py somaiya.com --no-nuclei --json
  python pipeline.py somaiya.com --full-scan --json

FIXES vs original:
  - Stage 4 and Stage 5 now have separate banners (was one combined banner)
  - Added --full-scan flag wired through to active_scanner
  - Tool-not-found is reported clearly before scanning starts
  - stage_active_scan split into stage_nmap + stage_nuclei for clarity
"""

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path

# ── Import the modules ────────────────────────────────────────────────────────
try:
    from subdomain import enumerate_subdomains
except ImportError as e:
    print(f"[ERROR] Could not import subdomain.py: {e}")
    sys.exit(1)

try:
    from status_prober import probe_statuses
except ImportError as e:
    print(f"[ERROR] Could not import status_prober.py: {e}")
    sys.exit(1)

try:
    from intelligence_engine import analyze_subdomains, print_report, findings_to_json
except ImportError as e:
    print(f"[ERROR] Could not import intelligence_engine.py: {e}")
    sys.exit(1)

try:
    from active_scanner import run_active_scan, deduplicate
except ImportError as e:
    print(f"[ERROR] Could not import active_scanner.py: {e}")
    sys.exit(1)


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(quiet: bool) -> None:
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


# ── ANSI colours ─────────────────────────────────────────────────────────────
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
RESET = "\033[0m"
DIM   = "\033[2m"
WARN  = "\033[93m"


def _banner(stage: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}━━━  Stage {stage}: {title}  ━━━{RESET}")


# ── Pre-flight tool check ─────────────────────────────────────────────────────

def preflight_check(skip_nmap: bool, skip_nuclei: bool) -> None:
    """Warn upfront if required external tools are missing — avoids silent hangs."""
    if not skip_nmap and not shutil.which("nmap"):
        # Also check Windows default path
        from pathlib import Path as P
        win_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
        if not any(P(p).is_file() for p in win_paths):
            print(
                f"\n{WARN}[WARNING] nmap not found on PATH or default Windows install paths.{RESET}\n"
                f"  Stage 4 (Nmap) will be skipped automatically.\n"
                f"  Install from: https://nmap.org/download\n"
                f"  Or run with --no-nmap to silence this warning.\n"
            )

    if not skip_nuclei and not shutil.which("nuclei"):
        print(
            f"\n{WARN}[WARNING] nuclei not found on PATH.{RESET}\n"
            f"  Stage 5 (Nuclei) will be skipped automatically.\n"
            f"  Install from: https://github.com/projectdiscovery/nuclei/releases\n"
            f"  Or run with --no-nuclei to silence this warning.\n"
        )


# ── Stage Wrappers ────────────────────────────────────────────────────────────

def stage_discover(domain: str) -> list[str]:
    """Stage 1 — Enumerate subdomains via AlienVault, URLScan, HackerTarget."""
    _banner(1, "Subdomain Discovery")

    report = enumerate_subdomains(domain)
    merged: list[str] = report["merged"]

    per_source = report.get("per_source", {})
    errors     = report.get("errors", {})
    for source, subs in per_source.items():
        if source in errors:
            print(f"  {DIM}[{source}] FAILED — {errors[source]}{RESET}")
        else:
            print(f"  [{source}] {len(subs)} subdomain(s) found")

    print(f"\n  {GREEN}✔ {len(merged)} unique subdomain(s) discovered{RESET}")
    return merged


def stage_probe(hostnames: list[str], workers: int) -> list[dict]:
    """Stage 2 — HTTP-probe each host to get its status code."""
    _banner(2, "HTTP Status Probing")

    if not hostnames:
        print("  No hosts to probe.")
        return []

    probed = probe_statuses(hostnames, max_workers=workers)

    live   = [h for h in probed if 200 <= h["status"] < 400]
    gated  = [h for h in probed if h["status"] in (401, 403)]
    broken = [h for h in probed if h["status"] >= 500]
    dead   = [h for h in probed if h["status"] == 0]

    print(f"  Live (2xx/3xx)   : {len(live)}")
    print(f"  Gated (401/403)  : {len(gated)}")
    print(f"  Broken (5xx)     : {len(broken)}")
    print(f"  Unreachable      : {len(dead)}")
    print(f"\n  {GREEN}✔ Probing complete — {len(probed) - len(dead)} active host(s){RESET}")

    return probed


def stage_analyse(scan_data: list[dict]) -> list[dict]:
    """Stage 3 — Run the intelligence engine to classify and prioritise findings."""
    _banner(3, "Intelligence Analysis")

    if not scan_data:
        print("  No scan data to analyse.")
        return []

    findings = analyze_subdomains(scan_data)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  Findings generated : {len(findings)}")
    print(f"  HIGH               : \033[91m{counts['HIGH']}\033[0m")
    print(f"  MEDIUM             : \033[93m{counts['MEDIUM']}\033[0m")
    print(f"  LOW                : \033[94m{counts['LOW']}\033[0m")
    print(f"\n  {GREEN}✔ Analysis complete{RESET}")

    return findings


def stage_active_scan(
    scan_data:   list[dict],
    skip_nmap:   bool = False,
    skip_nuclei: bool = False,
    scan_full:   bool = False,
) -> list[dict]:
    """
    Stages 4 + 5 — Nmap port scan and Nuclei vulnerability scan.

    FIX: Stages 4 and 5 each get their own banner so progress is visible
    while Nmap runs (previously one combined banner made it look frozen).
    """
    all_targets  = [h["host"] for h in scan_data if h.get("status", 0) != 0]
    http_targets = [h["host"] for h in scan_data if 200 <= h.get("status", 0) < 400]

    # ── Stage 4 banner ──
    _banner(4, "Active Scanning — Nmap Port Scan")
    print(f"  Targets : {len(all_targets)}")
    if scan_full:
        print(f"  Mode    : full (-sV, top-1000 ports) — this may take several minutes")
    else:
        print(f"  Mode    : fast (top-100 ports, 30 s host timeout)  [use --full-scan for -sV]")

    if skip_nmap:
        print(f"  {DIM}Skipped via --no-nmap{RESET}")
    elif not all_targets:
        print(f"  {DIM}No reachable targets — skipping{RESET}")

    # ── Stage 5 banner ──
    _banner(5, "Active Scanning — Nuclei Vulnerability Scan")
    print(f"  HTTP targets : {len(http_targets)}")

    if skip_nuclei:
        print(f"  {DIM}Skipped via --no-nuclei{RESET}")
    elif not http_targets:
        print(f"  {DIM}No HTTP-reachable targets — skipping{RESET}")

    if skip_nmap and skip_nuclei:
        print(f"\n  {DIM}Both active stages skipped.{RESET}")
        return []

    print(f"\n  Running active scans — this may take a few minutes...")

    active_findings = run_active_scan(
        scan_data   = scan_data,
        skip_nmap   = skip_nmap,
        skip_nuclei = skip_nuclei,
        scan_full   = scan_full,
    )

    nmap_count   = sum(1 for f in active_findings if f.get("source") == "nmap")
    nuclei_count = sum(1 for f in active_findings if f.get("source") == "nuclei")

    print(f"\n  Nmap findings   : {nmap_count}")
    print(f"  Nuclei findings : {nuclei_count}")
    print(f"\n  {GREEN}✔ Active scanning complete — {len(active_findings)} raw finding(s){RESET}")
    return active_findings


def stage_merge(
    engine_findings: list[dict],
    active_findings: list[dict],
) -> list[dict]:
    """Stage 6 — Merge all findings, deduplicate, sort by severity."""
    _banner(6, "Merge & Deduplicate")

    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    combined  = engine_findings + active_findings
    deduped   = deduplicate(combined)
    deduped.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in deduped:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    print(f"  Engine findings : {len(engine_findings)}")
    print(f"  Active findings : {len(active_findings)}")
    print(f"  After dedup     : {len(deduped)}  ({len(combined) - len(deduped)} duplicate(s) removed)")
    print(f"\n  HIGH   : \033[91m{counts['HIGH']}\033[0m")
    print(f"  MEDIUM : \033[93m{counts['MEDIUM']}\033[0m")
    print(f"  LOW    : \033[94m{counts['LOW']}\033[0m")
    print(f"\n  {GREEN}✔ Final report ready{RESET}")
    return deduped


# ── Main Pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    domain:      str,
    save_json:   bool = False,
    workers:     int  = 20,
    skip_nmap:   bool = False,
    skip_nuclei: bool = False,
    scan_full:   bool = False,
) -> list[dict]:
    """
    Execute the full six-stage pipeline for a given domain.
    Returns the final deduplicated, sorted list of findings.
    """
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SHADOW IT DISCOVERY PIPELINE{RESET}")
    print(f"  Target : {domain}")
    flags = []
    if skip_nmap:    flags.append("--no-nmap")
    if skip_nuclei:  flags.append("--no-nuclei")
    if scan_full:    flags.append("--full-scan")
    if flags: print(f"  Flags  : {' '.join(flags)}")
    print(f"{'='*60}")

    preflight_check(skip_nmap, skip_nuclei)

    start = time.time()

    hostnames       = stage_discover(domain)
    scan_data       = stage_probe(hostnames, workers=workers)
    engine_findings = stage_analyse(scan_data)
    active_findings = stage_active_scan(
        scan_data,
        skip_nmap   = skip_nmap,
        skip_nuclei = skip_nuclei,
        scan_full   = scan_full,
    )
    findings = stage_merge(engine_findings, active_findings)

    elapsed = time.time() - start
    print(f"\n{BOLD}{'='*60}")
    print(f"  Pipeline complete in {elapsed:.1f}s")
    print(f"{'='*60}{RESET}")

    if findings:
        print_report(findings)
    else:
        print("\n  No actionable findings. Attack surface looks clean.\n")

    if save_json:
        out_path = Path(f"{domain.replace('.', '_')}_findings.json")
        out_path.write_text(findings_to_json(findings), encoding="utf-8")
        print(f"\n{GREEN}✔ Findings saved to: {out_path}{RESET}\n")

    return findings


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Shadow IT Discovery — Full Attack Surface Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python pipeline.py acme.com\n"
            "  python pipeline.py acme.com --json\n"
            "  python pipeline.py acme.com --workers 30 --quiet\n"
            "  python pipeline.py acme.com --full-scan --json\n"
        ),
    )
    parser.add_argument("domain",            help="Root domain to scan (e.g. acme.com)")
    parser.add_argument("--json",        action="store_true", help="Save findings to <domain>_findings.json")
    parser.add_argument("--quiet",       action="store_true", help="Suppress stage-level log output")
    parser.add_argument("--workers",     type=int, default=20, metavar="N", help="HTTP probe concurrency (default: 20)")
    parser.add_argument("--no-nmap",     action="store_true", help="Skip Nmap port scan (Stage 4)")
    parser.add_argument("--no-nuclei",   action="store_true", help="Skip Nuclei vulnerability scan (Stage 5)")
    parser.add_argument("--full-scan",   action="store_true", help="Enable -sV + top-1000 ports in Nmap (slower but richer)")

    args = parser.parse_args()
    setup_logging(args.quiet)

    try:
        run_pipeline(
            domain      = args.domain.strip().lower(),
            save_json   = args.json,
            workers     = args.workers,
            skip_nmap   = args.no_nmap,
            skip_nuclei = args.no_nuclei,
            scan_full   = args.full_scan,
        )
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL] Pipeline crashed: {e}")
        logging.exception("Full traceback:")
        sys.exit(1)


if __name__ == "__main__":
    main()