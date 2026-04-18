"""
Shadow IT Discovery — Full Pipeline
=====================================
Chains all ten layers end-to-end:

  Stage 1  │ subdomain.py              → Discover all public subdomains
  Stage 2  │ status_prober.py          → Probe each host for HTTP status
  Stage 3  │ page_classifier.py        → Fetch + identify each live page
  Stage 4  │ intelligence_engine.py    → Rule-based risk classification
  Stage 5  │ active_scanner.py         → Nmap port/service scan
  Stage 6  │ active_scanner.py         → Nuclei vulnerability scan
  Stage 7  │ cloud_storage_exposure.py → Cloud bucket + open-directory scan
  Stage 8  │ sensitive_file_scanner.py → Sensitive file & backup exposure  ← NEW
  Stage 9  │ active_scanner.py         → Merge, deduplicate, sort findings
  Stage 10 │ pipeline.py               → Priority enrichment (P0/P1/P2)

Usage:
  python pipeline.py <domain>
  python pipeline.py <domain> --json          # save findings to JSON
  python pipeline.py <domain> --quiet         # suppress stage logs
  python pipeline.py <domain> --workers 30    # tune HTTP probe concurrency
  python pipeline.py <domain> --no-nmap       # skip Nmap stage
  python pipeline.py <domain> --no-nuclei     # skip Nuclei stage
  python pipeline.py <domain> --full-scan     # enable -sV + top-1000 Nmap scan
  python pipeline.py <domain> --no-classify   # skip page classification (faster)
  python pipeline.py <domain> --no-cloud      # skip cloud bucket scan
  python pipeline.py <domain> --no-files      # skip sensitive file scan

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

try:
    from cloud_storage_exposure import (
        full_scan as cloud_full_scan,
        check_open_directories,
        extract_base_name,
    )
    _CLOUD_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] cloud_storage_exposure.py not found — Stage 7 will be skipped: {e}")
    _CLOUD_AVAILABLE = False

try:
    from sensitive_file_scanner import scan_sensitive_files
    _FILE_SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] sensitive_file_scanner.py not found — Stage 8 will be skipped: {e}")
    _FILE_SCANNER_AVAILABLE = False


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

    print(f"\nHosts\n  {GREEN}✔ {len(merged)} found{RESET}")
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
    print(f"Open Ports\n  {GREEN}✔ {nmap_count} detected{RESET}")
    print(f"\n  Nmap findings   : {nmap_count}")
    print(f"  Nuclei findings : {nuclei_count}")
    print(f"\n  {GREEN}✔ Active scanning complete — {len(active_findings)} raw finding(s){RESET}")
    return active_findings


def stage_cloud_scan(
    domain:    str,
    scan_data: list[dict],
    skip_cloud: bool = False,
) -> list[dict]:
    """
    Stage 7 — Cloud Storage & Open Directory Exposure.

    Two-part scan:
      A) Root domain — bucket checks (S3 / Azure Blob / GCS) guessed from
         the base name.  Running on every subdomain would produce the same
         guesses, so we only run these once on the root domain.
      B) Every live subdomain — open-directory check on the actual web
         server at that host (Apache/Nginx/IIS directory listings, .git,
         /backup, /uploads, etc.).

    All raw cloud findings are converted to the pipeline's standard format:
      {id, severity, title, host, description, action, source, timestamp}
    CRITICAL severity from cloud checks is mapped to HIGH.
    """
    _banner(7, "Cloud Storage & Open Directory Exposure")

    if not _CLOUD_AVAILABLE or skip_cloud:
        reason = "module not found" if not _CLOUD_AVAILABLE else "skipped via --no-cloud"
        print(f"  {DIM}Skipped — {reason}{RESET}")
        return []

    import uuid
    from datetime import datetime, timezone

    def _id()  -> str: return str(uuid.uuid4())
    def _ts()  -> str: return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    def _sev(s: str) -> str:
        return {"CRITICAL": "HIGH"}.get(s.upper(), s.upper())

    findings: list[dict] = []

    # ── Part A: Bucket checks on root domain ──────────────────────────────────
    print(f"  Running bucket checks on root domain: {domain}")
    try:
        cloud_report = cloud_full_scan(domain, timeout=3.0, max_guesses=6, include_gcp=True)
    except Exception as exc:
        print(f"  {WARN}[WARN] Bucket checks failed: {exc}{RESET}")
        cloud_report = {}

    # public_buckets
    for item in cloud_report.get("public_buckets", []):
        findings.append({
            "id":          _id(),
            "severity":    "HIGH",
            "title":       f"Public Cloud Bucket Exposed — {item.get('service', '')}",
            "host":        domain,
            "description": (
                f"The bucket '{item.get('bucket')}' on {item.get('service')} "
                f"({item.get('url')}) is publicly accessible (HTTP 200). "
                f"Anyone on the internet can read its contents."
            ),
            "action": (
                "Immediately set the bucket ACL / policy to private. "
                "Audit its contents for sensitive data. "
                "Enable access logging and review who accessed it."
            ),
            "timestamp":   _ts(),
            "source":      "cloud",
        })

    # bucket_listings
    for item in cloud_report.get("bucket_listings", []):
        keys_preview = ", ".join(item.get("sample_objects", [])[:5])
        findings.append({
            "id":          _id(),
            "severity":    "HIGH",
            "title":       f"Bucket Directory Listing Enabled — {item.get('service', '')}",
            "host":        domain,
            "description": (
                f"Bucket '{item.get('bucket')}' on {item.get('service')} "
                f"({item.get('url')}) has directory listing enabled — "
                f"all stored objects can be enumerated. "
                + (f"Sample objects: {keys_preview}." if keys_preview else "")
            ),
            "action": (
                "Disable public listing on the bucket. "
                "Review listed objects for sensitive data and rotate any exposed credentials."
            ),
            "timestamp":   _ts(),
            "source":      "cloud",
        })

    # sensitive_files
    for item in cloud_report.get("sensitive_files", []):
        findings.append({
            "id":          _id(),
            "severity":    _sev(item.get("severity", "HIGH")),
            "title":       f"Sensitive File Exposed in Cloud Bucket — {item.get('file', '')}",
            "host":        domain,
            "description": (
                f"The file '{item.get('file')}' ({item.get('description')}) was found "
                f"publicly accessible at {item.get('url')} in the "
                f"'{item.get('bucket')}' {item.get('service')} bucket."
            ),
            "action": (
                "Remove or restrict access to the file immediately. "
                "Rotate any credentials or secrets it may contain. "
                "Audit the bucket for other sensitive files."
            ),
            "timestamp":   _ts(),
            "source":      "cloud",
        })

    # write_access
    for item in cloud_report.get("write_access", []):
        findings.append({
            "id":          _id(),
            "severity":    "HIGH",
            "title":       f"Unauthenticated Write Access on Cloud Bucket — {item.get('service', '')}",
            "host":        domain,
            "description": (
                f"Bucket '{item.get('bucket')}' on {item.get('service')} "
                f"accepts unauthenticated PUT requests. "
                f"Attackers can upload malware, deface content, or use it as a staging area."
            ),
            "action": (
                "Immediately revoke public write permissions on the bucket. "
                "Audit recent uploads for malicious content. "
                "Enable bucket versioning and access logging."
            ),
            "timestamp":   _ts(),
            "source":      "cloud",
        })

    # open_directories on root domain (from full_scan)
    for item in cloud_report.get("open_directories", []):
        findings.append({
            "id":          _id(),
            "severity":    _sev(item.get("severity", "MEDIUM")),
            "title":       f"Open Directory Listing on Web Server — {item.get('path', '')}",
            "host":        domain,
            "description": (
                f"Directory listing is enabled at {item.get('url')} on the web server. "
                f"Files in this directory are publicly browsable."
                + (f" Sample files: {', '.join(item.get('sample_files', [])[:5])}." if item.get('sample_files') else "")
            ),
            "action": (
                "Disable directory listing in your web server configuration (Apache: Options -Indexes; "
                "Nginx: remove autoindex on). Audit the directory for sensitive files."
            ),
            "timestamp":   _ts(),
            "source":      "cloud",
        })

    bucket_total = (
        len(cloud_report.get("public_buckets", [])) +
        len(cloud_report.get("bucket_listings", [])) +
        len(cloud_report.get("sensitive_files", [])) +
        len(cloud_report.get("write_access", [])) +
        len(cloud_report.get("open_directories", []))
    )
    print(f"  Root domain bucket/directory findings : {bucket_total}")

    # ── Part B: Open-directory check on every live subdomain ─────────────────
    live_subdomains = [
        h["host"] for h in scan_data
        if h.get("status", 0) != 0 and h["host"] != domain
    ]
    print(f"  Scanning {len(live_subdomains)} live subdomain(s) for open directories...")

    dir_count = 0
    for host in live_subdomains:
        try:
            hits = check_open_directories(host, timeout=3.0, max_workers=10)
        except Exception:
            hits = []
        for item in hits:
            findings.append({
                "id":          _id(),
                "severity":    _sev(item.get("severity", "MEDIUM")),
                "title":       f"Open Directory Listing on Subdomain — {item.get('path', '')}",
                "host":        host,
                "description": (
                    f"Directory listing is enabled at {item.get('url')}. "
                    f"Files in this path are publicly browsable."
                    + (f" Sample files: {', '.join(item.get('sample_files', [])[:5])}." if item.get('sample_files') else "")
                ),
                "action": (
                    "Disable directory listing in your web server config. "
                    "Audit the exposed path for credentials, backups, or config files."
                ),
                "timestamp":   _ts(),
                "source":      "cloud",
            })
            dir_count += 1

    print(f"  Subdomain open-directory findings     : {dir_count}")
    print(f"\n  {GREEN}✔ Cloud scan complete — {len(findings)} finding(s){RESET}")
    return findings


def stage_file_scan(
    scan_data:    list[dict],
    nuclei_exe:   str  = "",
    skip_files:   bool = False,
) -> list[dict]:
    """
    Stage 8 — Sensitive File & Backup Exposure Scanner.

    Probes every live subdomain for ~80 well-known sensitive paths
    (.env, credentials, git repos, backups, keys, config files, etc.)
    using parallel HTTP GET requests.

    Any path returning HTTP 200 is flagged. The response body is then
    inspected for real secret keywords (DB passwords, AWS keys, private
    keys, etc.) — confirmed secrets force severity to HIGH and are listed
    under `exposed_secrets` in the finding.

    If nuclei is installed and nuclei_sensitive_files.yaml is present
    alongside this script, nuclei is also run with that template for a
    second confirmation layer (content-aware matching).
    """
    _banner(8, "Sensitive File & Backup Exposure")

    if not _FILE_SCANNER_AVAILABLE or skip_files:
        reason = "module not found" if not _FILE_SCANNER_AVAILABLE else "skipped via --no-files"
        print(f"  {DIM}Skipped — {reason}{RESET}")
        return []

    live = [h for h in scan_data if 200 <= h.get("status", 0) < 500]
    print(f"  Hosts to scan  : {len(live)}")
    print(f"  Paths per host : ~80 sensitive paths")
    print(f"  Content check  : enabled (secret keyword inspection on every 200 response)")

    template_path = str(Path(__file__).parent / "nuclei_sensitive_files.yaml")
    nuclei_note   = ""
    if nuclei_exe and Path(template_path).exists():
        nuclei_note = f"  (+ Nuclei template: {Path(template_path).name})"
        print(f"  Nuclei confirm : {nuclei_note.strip()}")
    else:
        print(f"  {DIM}Nuclei template: not used (nuclei not found or template missing){RESET}")

    print()
    findings = scan_sensitive_files(
        scan_data     = scan_data,
        nuclei_exe    = nuclei_exe,
        template_path = template_path,
    )

    # ── Print inline preview of findings ─────────────────────────────────────
    if findings:
        SEV_C = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        confirmed = [f for f in findings if f.get("exposed_secrets")]
        print(f"  Files found    : {len(findings)}")
        if confirmed:
            print(f"  \033[91mSecret-confirmed : {len(confirmed)}  ← real credentials/keys found!{RESET}")
        print()
        for f in findings:
            c = SEV_C.get(f["severity"], "")
            secret_tag = f"  ⚠  {', '.join(f['exposed_secrets'][:2])}" if f.get("exposed_secrets") else ""
            print(f"  {c}[{f['severity']}]{RESET}  {f['host']}{f['file_path']}{secret_tag}")
    else:
        print(f"  {GREEN}No sensitive files found — paths are not publicly accessible.{RESET}")

    print(f"\n  {GREEN}✔ File scan complete — {len(findings)} finding(s){RESET}")
    return findings


def stage_merge(
    engine_findings: list[dict],
    active_findings: list[dict],
    cloud_findings:  list[dict] | None = None,
    file_findings:   list[dict] | None = None,
) -> list[dict]:
    """Stage 9 — Merge, deduplicate, sort."""
    _banner(9, "Merge & Deduplicate")

    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    combined  = engine_findings + active_findings + (cloud_findings or []) + (file_findings or [])
    deduped   = deduplicate(combined)
    deduped.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in deduped:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1

    print(f"  Engine findings : {len(engine_findings)}")
    print(f"  Active findings : {len(active_findings)}")
    print(f"  Cloud findings  : {len(cloud_findings or [])}")
    print(f"  File findings   : {len(file_findings or [])}")
    print(f"  After dedup     : {len(deduped)}  ({len(combined) - len(deduped)} duplicate(s) removed)")
    print(f"\n  HIGH   : \033[91m{counts['HIGH']}\033[0m")
    print(f"  MEDIUM : \033[93m{counts['MEDIUM']}\033[0m")
    print(f"  LOW    : \033[94m{counts['LOW']}\033[0m")
    print(f"\n  {GREEN}✔ Final report ready{RESET}")
    return deduped


# ── Priority Enrichment (Level 2 triage) ─────────────────────────────────────

# ---------------------------------------------------------------------------
# Scoring helpers
# Each factor returns 1-5.  Signals are matched against the finding's
# title + description (lower-cased) so the logic stays keyword-based and
# needs no external state.
# ---------------------------------------------------------------------------

_EXPLOIT_HIGH = [
    "write access", "writable", "unauthenticated", "no auth", "no mfa",
    "public bucket", "publicly accessible", "open redirect", "sqli",
    "rce", "remote code", "command injection", "deserialization",
    "directory listing", "index of /",
]
_EXPLOIT_MED = [
    "exposed panel", "admin panel", "database ui", "phpmyadmin",
    "kibana", "grafana", "jenkins", "gitlab", "ci/cd",
    "sensitive file", "credentials", "config", "backup",
]

_IMPACT_CRIT = [
    "database", "sql", "backup", "dump", "credentials", "secret",
    "private key", "ssh", "aws", "write access", "writable",
    "rce", "remote code", "command injection",
]
_IMPACT_HIGH = [
    "admin", "root", "superuser", "production", "prod",
    "payment", "financial", "pii", "personal data",
]

_EXPOSURE_FULL = [
    "public", "internet", "unauthenticated", "no auth",
    "open", "exposed", "accessible",
]
_EXPOSURE_PART = ["gated", "401", "403", "vpn", "internal", "restricted"]

_PRIV_ADMIN = [
    "admin", "root", "superuser", "write access", "writable",
    "rce", "remote code", "shell", "command",
]

_ASSET_CROWN = [
    "production", "prod", "payment", "database", "auth", "login",
    "credentials", "secret", "key", "backup", "core",
]
_ASSET_LOW = ["test", "staging", "dev", "demo", "sandbox", "legacy", "old"]

_CONF_HIGH = ["exposed", "confirmed", "200", "public", "verified"]
_CONF_LOW  = ["heuristic", "potential", "possible", "might", "could"]

_EFFORT_EASY = [
    "acl", "policy", "allowlist", "ip allow", "disable listing",
    "set private", "options -indexes", "autoindex off",
]
_EFFORT_HARD = [
    "redesign", "refactor", "architectural", "multi-week",
    "change window", "network acl", "firewall rule",
]


def _score_factor(text: str, high_signals: list[str], low_signals: list[str],
                  high_val: int = 5, mid_val: int = 3, low_val: int = 1) -> int:
    """Return high_val / mid_val / low_val depending on which signals match."""
    if any(s in text for s in high_signals):
        return high_val
    if any(s in text for s in low_signals):
        return mid_val
    return low_val


def _score_finding(finding: dict) -> dict:
    """
    Score a single finding across 7 factors and return an enrichment dict:
      exploitability, impact, exposure, privilege_potential,
      asset_criticality, evidence_confidence  → urgency_score (6-30)
      effort_to_fix                           → 1-5
      priority_score                          → 0-100
      fix_efficiency                          → urgency / effort
      priority_tier                           → P0 / P1 / P2 (HIGH only)
      remediation.recommended_sla             → 24h / 7d / 30d
      remediation.owner_category              → team string
      remediation.effort_level                → 1-5
    """
    sev   = finding.get("severity", "LOW").upper()
    title = (finding.get("title", "") + " " + finding.get("description", "")).lower()
    src   = finding.get("source", "").lower()

    # ── Factor 1: Exploitability (1-5) ───────────────────────────────────────
    exploitability = _score_factor(title, _EXPLOIT_HIGH, _EXPLOIT_MED)

    # ── Factor 2: Impact (1-5) ───────────────────────────────────────────────
    impact = _score_factor(title, _IMPACT_CRIT, _IMPACT_HIGH)

    # ── Factor 3: Exposure (1-5) ─────────────────────────────────────────────
    exposure = _score_factor(title, _EXPOSURE_FULL, _EXPOSURE_PART)

    # ── Factor 4: Privilege Potential (1-5) ──────────────────────────────────
    privilege = _score_factor(title, _PRIV_ADMIN, [], high_val=5, mid_val=3, low_val=2)

    # ── Factor 5: Asset Criticality (1-5) ────────────────────────────────────
    asset = _score_factor(title, _ASSET_CROWN, _ASSET_LOW, high_val=5, mid_val=3, low_val=2)

    # ── Factor 6: Evidence Confidence (1-5) ──────────────────────────────────
    # nuclei / cloud sources = confirmed signals; engine = heuristic
    if src in ("nuclei", "cloud"):
        confidence = _score_factor(title, _CONF_HIGH, _CONF_LOW, high_val=5, mid_val=4, low_val=3)
    elif src == "nmap":
        confidence = 4
    else:  # engine
        confidence = _score_factor(title, _CONF_HIGH, _CONF_LOW, high_val=3, mid_val=2, low_val=1)

    # ── Factor 7: Effort to Fix (1-5, inverted — higher = harder) ─────────────
    effort = _score_factor(title, _EFFORT_EASY, _EFFORT_HARD,
                           high_val=1, mid_val=3, low_val=4)
    # Quick wins from cloud/nmap config issues tend to be easy
    if src in ("cloud", "nmap") and effort == 4:
        effort = 2

    urgency_score  = exploitability + impact + exposure + privilege + asset + confidence  # 6-30
    priority_score = round((urgency_score / 30) * 100)
    fix_efficiency = round(urgency_score / max(effort, 1), 2)

    # ── Priority Tier (HIGH findings only) ────────────────────────────────────
    if sev == "HIGH":
        if priority_score >= 85:
            tier = "P0"
        elif priority_score >= 70:
            tier = "P1"
        else:
            tier = "P2"
    elif sev == "MEDIUM":
        tier = "P1" if priority_score >= 60 else "P2"
    else:  # LOW / INFO
        tier = "P2"

    # ── Recommended SLA ───────────────────────────────────────────────────────
    if tier == "P0":
        sla = "24h"
    elif tier == "P1":
        sla = "7 days"
    else:
        sla = "30 days"

    # ── Owner Category ────────────────────────────────────────────────────────
    if any(k in title for k in ("bucket", "s3", "azure blob", "gcs", "cloud", "directory listing")):
        owner = "Infrastructure / CloudOps"
    elif any(k in title for k in ("ssh", "rdp", "port", "firewall", "network", "nmap")):
        owner = "Network / ITOps"
    elif any(k in title for k in ("credentials", "mfa", "auth", "iam", "secret", "key", "token")):
        owner = "Identity / IAM"
    elif src in ("nuclei", "engine"):
        owner = "AppSec / Dev Team"
    else:
        owner = "Infrastructure / CloudOps"

    return {
        "priority_tier":  tier,
        "priority_score": priority_score,
        "fix_efficiency": fix_efficiency,
        "_urgency_factors": {
            "exploitability":      exploitability,
            "impact":              impact,
            "exposure":            exposure,
            "privilege_potential": privilege,
            "asset_criticality":   asset,
            "evidence_confidence": confidence,
        },
        "remediation": {
            "recommended_sla":  sla,
            "owner_category":   owner,
            "effort_level":     effort,
        },
    }


def enrich_priority(findings: list[dict]) -> list[dict]:
    """
    Stage 9 (post-processing) — Level 2 Priority Enrichment.

    Additively enriches every finding with:
      priority_tier   — P0 / P1 / P2
      priority_score  — 0-100
      fix_efficiency  — urgency / effort  (higher = quicker win)
      remediation     — { recommended_sla, owner_category, effort_level }

    Re-sorts the list by:
      1. Severity      (HIGH → MEDIUM → LOW)
      2. Priority Tier (P0 → P1 → P2)
      3. Fix Efficiency descending (quick wins first within same tier)

    No existing fields are modified.
    """
    _banner(10, "Priority Enrichment (P0 / P1 / P2 Triage)")

    if not findings:
        print(f"  {DIM}No findings to enrich.{RESET}")
        return findings

    for f in findings:
        enrichment = _score_finding(f)
        f.update(enrichment)

    SEV_ORDER  = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    TIER_ORDER = {"P0": 0, "P1": 1, "P2": 2}

    findings.sort(key=lambda f: (
        SEV_ORDER.get(f.get("severity", "INFO"), 99),
        TIER_ORDER.get(f.get("priority_tier", "P2"), 9),
        -f.get("fix_efficiency", 0),
    ))

    # ── Summary table ─────────────────────────────────────────────────────────
    from collections import Counter
    high_findings = [f for f in findings if f.get("severity") == "HIGH"]
    tier_counts   = Counter(f.get("priority_tier", "P2") for f in high_findings)

    print(f"  Total findings enriched : {len(findings)}")
    if high_findings:
        print(f"\n  HIGH findings breakdown:")
        for tier in ("P0", "P1", "P2"):
            n = tier_counts.get(tier, 0)
            if n:
                sla = {"P0": "24h", "P1": "7 days", "P2": "30 days"}[tier]
                color = {"P0": "\033[91m", "P1": "\033[93m", "P2": "\033[94m"}[tier]
                print(f"    {color}{tier}{RESET}  {n:3} finding(s)  →  SLA: {sla}")

    p0_all = [f for f in findings if f.get("priority_tier") == "P0"]
    if p0_all:
        print(f"\n  {BOLD}Top P0 quick wins (highest Fix Efficiency):{RESET}")
        for f in sorted(p0_all, key=lambda x: -x.get("fix_efficiency", 0))[:5]:
            print(
                f"    [{f.get('severity','?'):6}] "
                f"score={f.get('priority_score'):3}  "
                f"eff={f.get('fix_efficiency'):5.1f}  "
                f"{f.get('title','')[:70]}"
            )

    print(f"\n  {GREEN}✔ Priority enrichment complete{RESET}")
    return findings


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
    skip_cloud:    bool = False,
    skip_files:    bool = False,
) -> list[dict]:
    """Execute the full ten-stage pipeline and return final findings."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SHADOW IT DISCOVERY PIPELINE{RESET}")
    print(f"  Target : {domain}")
    flags = []
    if demo_mode:      flags.append("--demo")
    if skip_classify:  flags.append("--no-classify")
    if skip_nmap:      flags.append("--no-nmap")
    if skip_nuclei:    flags.append("--no-nuclei")
    if scan_full:      flags.append("--full-scan")
    if skip_cloud:     flags.append("--no-cloud")
    if skip_files:     flags.append("--no-files")
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

    # Stage 7 — Cloud storage & open directory exposure
    cloud_findings = stage_cloud_scan(domain, scan_data, skip_cloud=skip_cloud)

    # Stage 8 — Sensitive file & backup exposure
    file_findings = stage_file_scan(
        scan_data,
        nuclei_exe = NUCLEI_PATH if Path(NUCLEI_PATH).is_file() else (shutil.which("nuclei") or ""),
        skip_files = skip_files,
    )

    # Stage 9 — Merge + deduplicate + sort
    findings = stage_merge(engine_findings, active_findings, cloud_findings, file_findings)

    # Stage 10 — Level 2 priority enrichment (P0/P1/P2, score, SLA, owner)
    findings = enrich_priority(findings)

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
    parser.add_argument("--no-cloud",      action="store_true", help="Skip Stage 7 cloud storage & open directory scan")
    parser.add_argument("--no-files",      action="store_true", help="Skip Stage 8 sensitive file & backup exposure scan")
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
            skip_cloud    = args.no_cloud,
            skip_files    = args.no_files,
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