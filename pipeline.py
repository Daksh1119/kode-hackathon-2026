"""
Shadow IT Discovery — Full Pipeline
=====================================
Chains all seven layers end-to-end:

  Stage 1 │ subdomain.py          → Discover all public subdomains
  Stage 2 │ status_prober.py      → Probe each host for HTTP status
  Stage 3 │ page_classifier.py    → Fetch + identify each live page  ← NEW
  Stage 4 │ intelligence_engine.py→ Rule-based risk classification (uses page_type)
  Stage 5 │ active_scanner.py     → Nmap port/service scan
  Stage 6 │ active_scanner.py     → Nuclei vulnerability scan
  Stage 7 │ active_scanner.py     → Merge, deduplicate, sort all findings

Usage:
  python pipeline.py <domain>
  python pipeline.py <domain> --json          # save findings to JSON
  python pipeline.py <domain> --quiet         # suppress stage logs
  python pipeline.py <domain> --workers 30    # tune HTTP probe concurrency
  python pipeline.py <domain> --no-nmap       # skip Nmap stage
  python pipeline.py <domain> --no-nuclei     # skip Nuclei stage
  python pipeline.py <domain> --full-scan     # enable -sV + top-1000 Nmap scan
  python pipeline.py <domain> --no-classify   # skip page classification (faster)

Example:
  python pipeline.py somaiya.com
  python pipeline.py somaiya.com --json
  python pipeline.py somaiya.com --no-nuclei --json
  python pipeline.py somaiya.com --full-scan --json
"""

import argparse
import logging
import shutil
import sys
import time
from pathlib import Path

# ── Module imports ────────────────────────────────────────────────────────────
try:
    from subdomain import enumerate_subdomains
except ImportError as e:
    print(f"[ERROR] Could not import subdomain.py: {e}"); sys.exit(1)

try:
    from status_prober import probe_statuses
except ImportError as e:
    print(f"[ERROR] Could not import status_prober.py: {e}"); sys.exit(1)

try:
    from page_classifier import classify_pages, PAGE_TYPE_META
except ImportError as e:
    print(f"[ERROR] Could not import page_classifier.py: {e}"); sys.exit(1)

try:
    from intelligence_engine import analyze_subdomains, print_report, findings_to_json
except ImportError as e:
    print(f"[ERROR] Could not import intelligence_engine.py: {e}"); sys.exit(1)

try:
    from active_scanner import run_active_scan, deduplicate
except ImportError as e:
    print(f"[ERROR] Could not import active_scanner.py: {e}"); sys.exit(1)


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(quiet: bool) -> None:
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


# ── ANSI colours ──────────────────────────────────────────────────────────────
BOLD  = "\033[1m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
RESET = "\033[0m"
DIM   = "\033[2m"
WARN  = "\033[93m"

NUCLEI_PATH = r"C:\Users\daksh_769tz6y\go\bin\nuclei.exe"


def _banner(stage: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}━━━  Stage {stage}: {title}  ━━━{RESET}")


# ── Pre-flight tool check ─────────────────────────────────────────────────────

def preflight_check(skip_nmap: bool, skip_nuclei: bool) -> None:
    if not skip_nmap and not shutil.which("nmap"):
        win_paths = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
        if not any(Path(p).is_file() for p in win_paths):
            print(
                f"\n{WARN}[WARNING] nmap not found — Stage 5 will be skipped automatically.{RESET}\n"
                f"  Install: https://nmap.org/download  or use --no-nmap to silence this.\n"
            )
    if not skip_nuclei and not (Path(NUCLEI_PATH).is_file() or shutil.which("nuclei")):
        print(
            f"\n{WARN}[WARNING] nuclei not found — Stage 6 will be skipped automatically.{RESET}\n"
            f"  Install: https://github.com/projectdiscovery/nuclei/releases  or use --no-nuclei.\n"
        )


# ── Stage wrappers ────────────────────────────────────────────────────────────

def stage_discover(domain: str) -> list[str]:
    """Stage 1 — Enumerate subdomains."""
    _banner(1, "Subdomain Discovery")
    report  = enumerate_subdomains(domain)
    merged: list[str] = report["merged"]

    for source, subs in report.get("per_source", {}).items():
        if source in report.get("errors", {}):
            print(f"  {DIM}[{source}] FAILED — {report['errors'][source]}{RESET}")
        else:
            print(f"  [{source}] {len(subs)} subdomain(s) found")

    print(f"\n  {GREEN}✔ {len(merged)} unique subdomain(s) discovered{RESET}")
    return merged


def stage_probe(hostnames: list[str], workers: int) -> list[dict]:
    """Stage 2 — HTTP status probe."""
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


def stage_classify(scan_data: list[dict], workers: int) -> list[dict]:
    """
    Stage 3 — Page classification.

    Fetches the actual content of each live host and identifies what kind
    of page or service it is (login, admin panel, API, directory listing, etc.).

    This stage enriches every host dict with three new fields:
      page_type    — e.g. "login", "admin_panel", "api_json"
      page_title   — text from the HTML <title> tag
      page_signals — human-readable signals that drove the classification
    """
    _banner(3, "Page / Service Identification")

    live = [h for h in scan_data if h.get("status", 0) != 0]
    dead = [h for h in scan_data if h.get("status", 0) == 0]

    print(f"  Fetching content for {len(live)} live host(s)...")
    print(f"  ({len(dead)} unreachable hosts skipped)\n")

    enriched = classify_pages(scan_data, max_workers=workers)

    # Summary table
    from collections import Counter
    counts = Counter(h.get("page_type", "unknown") for h in enriched if h.get("status", 0) != 0)

    # Show in a priority order: interesting types first
    DISPLAY_ORDER = [
        "login", "admin_panel", "database_ui", "file_listing", "ci_cd",
        "api_json", "api_docs", "monitoring", "dashboard",
        "staging", "docs", "web_app", "error_page", "static_site", "unknown",
    ]

    rows_shown = 0
    for page_type in DISPLAY_ORDER:
        if page_type in counts:
            label = PAGE_TYPE_META.get(page_type, (page_type.replace("_", " ").title(), ""))[0]
            sev   = PAGE_TYPE_META.get(page_type, ("", "LOW"))[1]
            sev_colour = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}.get(sev, "")
            print(f"  {sev_colour}{counts[page_type]:3}×  {label}{RESET}")
            rows_shown += 1

    # Catch any types not in DISPLAY_ORDER
    for page_type, n in counts.items():
        if page_type not in DISPLAY_ORDER:
            print(f"  {n:3}×  {page_type}")

    if rows_shown == 0:
        print("  (all hosts unreachable — no pages classified)")

    print(f"\n  {GREEN}✔ Page classification complete{RESET}")
    return enriched


def stage_analyse(scan_data: list[dict]) -> list[dict]:
    """Stage 4 — Intelligence analysis (now page-type-aware)."""
    _banner(4, "Intelligence Analysis")

    if not scan_data:
        print("  No scan data to analyse.")
        return []

    findings = analyze_subdomains(scan_data)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Count how many findings were driven by page_type vs keyword
    page_driven = sum(
        1 for f in findings
        if f.get("page_type") and "page_" in f.get("title", "").lower().replace(" ", "_")
        or f.get("source") == "engine" and f.get("page_type")
    )

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
    demo_mode:   bool = False,
) -> list[dict]:
    """Stages 5 + 6 — Nmap and Nuclei."""
    all_targets  = [h["host"] for h in scan_data if h.get("status", 0) != 0]
    http_targets = [h["host"] for h in scan_data if 200 <= h.get("status", 0) < 400]

    _banner(5, "Active Scanning — Nmap Port Scan")
    print(f"  Targets : {len(all_targets)}")
    if scan_full:
        mode_str = "full  (top-1000 ports, -sV, 30s/host) — ~5-10 min"
    elif demo_mode:
        mode_str = "demo  (24 critical ports, 5s/host, --min-rate 2000) — ~15-30s"
    else:
        mode_str = "fast  (24 critical ports, 10s/host, --min-rate 2000) — ~30-60s"
    print(f"  Mode    : {mode_str}")
    if skip_nmap:
        print(f"  {DIM}Skipped via --no-nmap{RESET}")

    _banner(6, "Active Scanning — Nuclei Vulnerability Scan")
    print(f"  HTTP targets : {len(http_targets)}")
    if demo_mode:
        nuclei_mode = "demo  (3s/template, 300 req/s, -no-interactsh, panel/exposure tags) — ~30-60s"
    else:
        nuclei_mode = "fast  (5s/template, 150 req/s, -no-interactsh, panel/exposure tags) — ~60-120s"
    print(f"  Mode         : {nuclei_mode}")
    if skip_nuclei:
        print(f"  {DIM}Skipped via --no-nuclei{RESET}")

    if skip_nmap and skip_nuclei:
        print(f"\n  {DIM}Both active stages skipped.{RESET}")
        return []

    print(f"\n  Running active scans...")

    active_findings = run_active_scan(
        scan_data   = scan_data,
        skip_nmap   = skip_nmap,
        skip_nuclei = skip_nuclei,
        scan_full   = scan_full,
        demo_mode   = demo_mode,
    )

    nmap_count   = sum(1 for f in active_findings if f.get("source") == "nmap")
    nuclei_count = sum(1 for f in active_findings if f.get("source") == "nuclei")
    print(f"\n  Nmap findings   : {nmap_count}")
    print(f"  Nuclei findings : {nuclei_count}")
    print(f"\n  {GREEN}✔ Active scanning complete — {len(active_findings)} raw finding(s){RESET}")
    return active_findings


def stage_merge(engine_findings: list[dict], active_findings: list[dict]) -> list[dict]:
    """Stage 7 — Merge, deduplicate, sort."""
    _banner(7, "Merge & Deduplicate")

    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    combined  = engine_findings + active_findings
    deduped   = deduplicate(combined)
    deduped.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in deduped:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1

    print(f"  Engine findings : {len(engine_findings)}")
    print(f"  Active findings : {len(active_findings)}")
    print(f"  After dedup     : {len(deduped)}  ({len(combined) - len(deduped)} duplicate(s) removed)")
    print(f"\n  HIGH   : \033[91m{counts['HIGH']}\033[0m")
    print(f"  MEDIUM : \033[93m{counts['MEDIUM']}\033[0m")
    print(f"  LOW    : \033[94m{counts['LOW']}\033[0m")
    print(f"\n  {GREEN}✔ Final report ready{RESET}")
    return deduped


# ── Full pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    domain:        str,
    save_json:     bool = False,
    workers:       int  = 20,
    skip_classify: bool = False,
    skip_nmap:     bool = False,
    skip_nuclei:   bool = False,
    scan_full:     bool = False,
    demo_mode:     bool = False,
) -> list[dict]:
    """Execute the full seven-stage pipeline and return final findings."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SHADOW IT DISCOVERY PIPELINE{RESET}")
    print(f"  Target : {domain}")
    flags = []
    if demo_mode:      flags.append("--demo")
    if skip_classify:  flags.append("--no-classify")
    if skip_nmap:      flags.append("--no-nmap")
    if skip_nuclei:    flags.append("--no-nuclei")
    if scan_full:      flags.append("--full-scan")
    if flags: print(f"  Flags  : {' '.join(flags)}")
    if demo_mode: print(f"  {CYAN}Demo mode: tightest timeouts — target ~60-90s total{RESET}")
    print(f"{'='*60}")

    preflight_check(skip_nmap, skip_nuclei)
    start = time.time()

    # Stage 1 — Subdomain discovery
    hostnames = stage_discover(domain)

    # Stage 2 — HTTP status probing
    scan_data = stage_probe(hostnames, workers=workers)

    # Stage 3 — Page / service identification
    if not skip_classify:
        scan_data = stage_classify(scan_data, workers=workers)
    else:
        _banner(3, "Page / Service Identification")
        print(f"  {DIM}Skipped via --no-classify{RESET}")

    # Stage 4 — Intelligence analysis
    engine_findings = stage_analyse(scan_data)

    # Stages 5 + 6 — Active scanning
    active_findings = stage_active_scan(
        scan_data,
        skip_nmap   = skip_nmap,
        skip_nuclei = skip_nuclei,
        scan_full   = scan_full,
        demo_mode   = demo_mode,
    )

    # Stage 7 — Merge + deduplicate + sort
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
            "  python pipeline.py acme.com --no-classify --no-nuclei\n"
            "  python pipeline.py acme.com --full-scan --json\n"
        ),
    )
    parser.add_argument("domain",               help="Root domain to scan (e.g. acme.com)")
    parser.add_argument("--json",          action="store_true", help="Save findings to <domain>_findings.json")
    parser.add_argument("--quiet",         action="store_true", help="Suppress stage-level log output")
    parser.add_argument("--workers",       type=int, default=20, metavar="N", help="Concurrency for HTTP probing and page classification (default: 20)")
    parser.add_argument("--no-classify",   action="store_true", help="Skip Stage 3 page classification (faster, less precise)")
    parser.add_argument("--no-nmap",       action="store_true", help="Skip Nmap port scan (Stage 5)")
    parser.add_argument("--no-nuclei",     action="store_true", help="Skip Nuclei vulnerability scan (Stage 6)")
    parser.add_argument("--full-scan",     action="store_true", help="Enable -sV + top-1000 in Nmap (slower but richer)")
    parser.add_argument("--demo",          action="store_true", help="Hackathon/demo mode: tightest timeouts, completes in ~60-90s")

    args = parser.parse_args()
    setup_logging(args.quiet)

    try:
        run_pipeline(
            domain        = args.domain.strip().lower(),
            save_json     = args.json,
            workers       = args.workers,
            skip_classify = args.no_classify,
            skip_nmap     = args.no_nmap,
            skip_nuclei   = args.no_nuclei,
            scan_full     = args.full_scan,
            demo_mode     = args.demo,
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