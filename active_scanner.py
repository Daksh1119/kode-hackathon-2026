"""
Active Scanner — Stages 4 & 5
==============================
Stage 4 │ Nmap    → open ports and running services
Stage 5 │ Nuclei  → known vulnerability templates

Both tools are called via subprocess (no shell=True — safe from injection).
Both stages are fault-tolerant: if a tool fails or its output file is missing,
the pipeline continues and that stage simply contributes zero findings.

Windows paths handled automatically:
  Nmap   → C:\\Program Files (x86)\\Nmap\\nmap.exe  (falls back to PATH)
  Nuclei → nuclei  (already on PATH per user confirmation)

FIXES vs original:
  - Added --host-timeout 30s  → Nmap no longer hangs on a single slow host
  - Added --max-retries 1     → stops Nmap retrying unresponsive ports
  - Reduced --top-ports 1000 → 100  → ~10× faster with comparable coverage
  - Removed -sV by default    → service detection is slow; use scan_full=True to re-enable
  - Nuclei v3 compat          → tries -o flag (v3) then -json-export (v2) automatically
  - Removed unreachable code  → dead return in status_prober integration removed
  - Tool availability guard   → warns immediately if nmap/nuclei not found; skips cleanly
"""

import json
import logging
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("active_scanner")

# ── Tool Paths ────────────────────────────────────────────────────────────────
_NMAP_CANDIDATES = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "nmap",
]

NUCLEI_PATH = r"C:\Users\daksh_769tz6y\go\bin\nuclei.exe"


def _find_nmap() -> str:
    for candidate in _NMAP_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return str(path)
    if shutil.which("nmap"):
        return "nmap"
    return ""


def _find_nuclei() -> str:
    if Path(NUCLEI_PATH).is_file():
        return NUCLEI_PATH
    return shutil.which("nuclei") or ""


# ── Port → Risk Mapping ───────────────────────────────────────────────────────

HIGH_PORTS = {
    21:    "FTP — cleartext file transfer",
    22:    "SSH — remote shell access",
    23:    "Telnet — cleartext remote access",
    25:    "SMTP — mail relay",
    53:    "DNS — potentially open resolver",
    135:   "RPC — Windows remote procedure call",
    139:   "NetBIOS — Windows file sharing",
    445:   "SMB — Windows file sharing (EternalBlue target)",
    1433:  "MSSQL — database",
    1521:  "Oracle DB — database",
    3306:  "MySQL — database",
    3389:  "RDP — remote desktop",
    5432:  "PostgreSQL — database",
    5900:  "VNC — remote desktop",
    6379:  "Redis — in-memory database (often unauthenticated)",
    27017: "MongoDB — database (often unauthenticated)",
}

MEDIUM_PORTS = {
    80:    "HTTP — unencrypted web traffic",
    443:   "HTTPS — encrypted web traffic",
    8080:  "HTTP alternate — often dev/proxy",
    8443:  "HTTPS alternate — often dev/proxy",
    8888:  "HTTP alternate — often Jupyter/proxy",
    9200:  "Elasticsearch — search engine API",
    9300:  "Elasticsearch cluster comms",
    11211: "Memcached — caching (often unauthenticated)",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_id() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _run(cmd: list[str], label: str, timeout: int = 300) -> bool:
    """
    Run a subprocess command safely (no shell=True).
    Returns True on success, False on any failure.

    FIX: default timeout reduced from 600 → 300s; callers that need more
    still pass their own value.
    """
    log.info(f"[{label}] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            log.warning(f"[{label}] Exited with code {result.returncode}")
            if result.stderr:
                log.debug(f"[{label}] stderr: {result.stderr[:500]}")
        return result.returncode == 0
    except FileNotFoundError:
        log.error(f"[{label}] Tool not found. Is it installed and on PATH?")
        return False
    except subprocess.TimeoutExpired:
        log.error(f"[{label}] Timed out after {timeout}s — results in partial output file may still be usable")
        return False
    except Exception as e:
        log.error(f"[{label}] Unexpected error: {e}")
        return False


# ── Targets File ──────────────────────────────────────────────────────────────

def write_targets(hosts: list[str], path: str = "targets.txt") -> str:
    Path(path).write_text("\n".join(hosts), encoding="utf-8")
    log.info(f"Wrote {len(hosts)} target(s) to {path}")
    return path


# ── Stage 4: Nmap ─────────────────────────────────────────────────────────────

# Explicit port list — only the ports we actually classify as HIGH or MEDIUM.
# Scanning 20 specific ports is ~5× faster than --top-ports 100.
_FAST_PORTS = ",".join(str(p) for p in sorted(
    list(HIGH_PORTS.keys()) + list(MEDIUM_PORTS.keys())
))
# e.g. "21,22,23,25,53,80,135,139,443,445,1433,1521,3306,3389,5432,5900,
#        6379,8080,8443,8888,9200,9300,11211,27017"


def run_nmap(
    targets_file: str = "targets.txt",
    output_xml:   str = "nmap.xml",
    scan_full:    bool = False,
    demo_mode:    bool = False,
) -> bool:
    """
    Run Nmap against all targets.

    Speed tiers:
      demo  → scan only the 24 ports we classify, host-timeout 5s,  ~15-30s total
      fast  → same port list, host-timeout 10s  (default)
      full  → --top-ports 1000 + -sV,           host-timeout 30s   (--full-scan flag)

    Key speed flags always present:
      -T4              aggressive timing
      -Pn              skip host-discovery (treat all as online)
      --min-rate 2000  force ≥2000 pkts/s — biggest speed win on WAN
      --max-retries 1  no port retries
      --open           only report open ports (skip closed/filtered output)
    """
    nmap = _find_nmap()
    if not nmap:
        log.error(
            "[Nmap] nmap not found. "
            "Install from https://nmap.org/download or add to PATH. "
            "Stage 4 will be skipped."
        )
        return False

    if scan_full:
        port_args     = ["--top-ports", "1000"]
        host_timeout  = "30s"
        extra         = ["-sV", "--version-intensity", "0"]  # version detection, minimal intensity
        proc_timeout  = 600
    elif demo_mode:
        port_args     = ["-p", _FAST_PORTS]
        host_timeout  = "5s"
        extra         = []
        proc_timeout  = 60
    else:
        port_args     = ["-p", _FAST_PORTS]
        host_timeout  = "10s"
        extra         = []
        proc_timeout  = 180

    cmd = [
        nmap,
        "-T4",
        "-Pn",
        "--min-rate",    "2000",       # force fast packet rate — biggest WAN speed win
        "--max-retries", "1",          # no port retries
        "--host-timeout", host_timeout,
        "--open",                       # only show open ports — skips filtered noise
        *extra,
        *port_args,
        "-oX", output_xml,
        "-iL", targets_file,
    ]

    return _run(cmd, "Nmap", timeout=proc_timeout)


def parse_nmap(xml_file: str = "nmap.xml") -> list[dict]:
    """
    Parse Nmap XML output.
    Returns list of {host, port, service, protocol, source="nmap"}.

    FIX: also attempts to parse partial XML if the scan was interrupted
    (Nmap writes valid XML incrementally up to the last closed <host> tag).
    """
    path = Path(xml_file)
    if not path.exists():
        log.warning(f"[Nmap] Output file not found: {xml_file}")
        return []

    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        log.warning("[Nmap] Output file is empty")
        return []

    # Nmap XML is well-formed only if the scan completed; if timed-out the
    # closing </nmaprun> tag may be missing.  Patch it before parsing.
    if "</nmaprun>" not in raw:
        raw += "\n</nmaprun>"

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        log.error(f"[Nmap] Failed to parse XML: {e}")
        return []

    results = []
    for host_el in root.findall("host"):
        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        if not hostname:
            addr_el  = host_el.find("address")
            hostname = addr_el.get("addr") if addr_el is not None else "unknown"

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id    = int(port_el.get("portid", 0))
            protocol   = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service    = service_el.get("name",    "unknown") if service_el is not None else "unknown"
            product    = service_el.get("product", "")        if service_el is not None else ""
            version    = service_el.get("version", "")        if service_el is not None else ""

            results.append({
                "host":     hostname,
                "port":     port_id,
                "protocol": protocol,
                "service":  service,
                "product":  f"{product} {version}".strip(),
                "source":   "nmap",
            })

    log.info(f"[Nmap] Parsed {len(results)} open port(s)")
    return results


def nmap_to_findings(nmap_data: list[dict]) -> list[dict]:
    """Convert raw Nmap port data into the standard finding format."""
    findings = []

    for item in nmap_data:
        port    = item["port"]
        host    = item["host"]
        service = item["service"]
        product = item.get("product", "")

        service_display = f"{product} ({service})" if product else service

        if port in HIGH_PORTS:
            severity    = "HIGH"
            risk_reason = HIGH_PORTS[port]
            title       = f"Sensitive Port {port} Open — {service.upper()}"
            description = (
                f"Port {port}/{item['protocol']} ({service_display}) is publicly accessible "
                f"on {host}. {risk_reason}. Sensitive services exposed to the internet are "
                f"prime targets for brute-force, exploitation, and lateral movement."
            )
            action = (
                f"Immediately restrict port {port} to internal network or VPN only via firewall rules. "
                f"If this service is not needed, disable it entirely."
            )
        elif port in MEDIUM_PORTS:
            severity    = "MEDIUM"
            risk_reason = MEDIUM_PORTS[port]
            title       = f"Port {port} Open — {service.upper()}"
            description = (
                f"Port {port}/{item['protocol']} ({service_display}) is open on {host}. "
                f"{risk_reason}. Verify this is intentionally public."
            )
            action = (
                f"Confirm port {port} is intentionally internet-facing. "
                f"Ensure the service is up to date and properly configured."
            )
        else:
            severity    = "LOW"
            title       = f"Open Port {port} Detected"
            description = (
                f"Port {port}/{item['protocol']} ({service_display}) is open on {host}. "
                f"Verify this port is intentionally exposed."
            )
            action = "Review whether this port needs to be internet-facing."

        findings.append({
            "id":          _generate_id(),
            "severity":    severity,
            "title":       title,
            "host":        host,
            "description": description,
            "action":      action,
            "timestamp":   _now(),
            "source":      "nmap",
            "port":        port,
        })

    return findings


# ── Stage 5: Nuclei ───────────────────────────────────────────────────────────

# Templates scoped to fast, relevant categories only.
# Avoids thousands of slow CVE / network templates that aren't useful for
# attack-surface discovery.
_NUCLEI_FAST_TAGS = "panel,exposure,misconfig,takeover,default-login,login,tech"

# Tags to explicitly EXCLUDE — ssl/tls checks wait for TLS handshakes (slow)
_NUCLEI_EXCLUDE_TAGS = "ssl,tls,dns,fuzzing,dos"


def run_nuclei(
    targets_file: str  = "targets.txt",
    output_json:  str  = "nuclei.jsonl",
    demo_mode:    bool = False,
) -> bool:
    """
    Run Nuclei against HTTP-reachable targets.

    Speed fixes applied (every mode):
      -no-interactsh       BIGGEST WIN — disables OOB/OAST callbacks that wait
                           for DNS pingbacks (adds seconds of delay per template)
      -timeout 5           5s per template request (default is 10s)
      -rate-limit 150      150 req/s (default is much lower)
      -bulk-size 50        process 50 hosts per template batch
      -concurrency 50      run 50 templates in parallel
      -etags ssl,tls,dns   skip slow network/crypto checks
      -tags panel,...      only run fast discovery templates (not all CVEs)

    demo_mode additionally:
      -timeout 3           3s per template
      -rate-limit 300      push req/s higher
      -concurrency 100     max parallelism

    subprocess timeout:
      demo → 90s  |  normal → 300s  (was 1200s = 20 minutes!)
    """
    nuclei = _find_nuclei()
    if not nuclei:
        log.error(
            "[Nuclei] nuclei not found on PATH. "
            "Install from https://github.com/projectdiscovery/nuclei/releases. "
            "Stage 5 will be skipped."
        )
        return False

    # Detect v2 vs v3 to pick the right output flag
    try:
        ver_result = subprocess.run(
            [nuclei, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        ver_output = ver_result.stdout + ver_result.stderr
        is_v3 = "3." in ver_output
    except Exception:
        is_v3 = True  # default to v3 (user confirmed v3.8.0)

    per_template_timeout = "3" if demo_mode else "5"
    rate_limit           = "300" if demo_mode else "150"
    concurrency          = "100" if demo_mode else "50"
    bulk_size            = "100" if demo_mode else "50"
    proc_timeout         = 90   if demo_mode else 300   # was 1200!

    # Flags common to both v2 and v3
    common_speed_flags = [
        "-no-interactsh",              # kills OOB wait time — biggest single win
        "-timeout",    per_template_timeout,
        "-rate-limit", rate_limit,
        "-bulk-size",  bulk_size,
        "-concurrency", concurrency,
        "-tags",       _NUCLEI_FAST_TAGS,   # only run relevant template categories
        "-etags",      _NUCLEI_EXCLUDE_TAGS, # skip slow ssl/tls/dns/fuzz templates
        "-severity",   "critical,high,medium",
        "-silent",
        "-nc",
    ]

    if is_v3:
        cmd = [nuclei, "-l", targets_file, "-o", output_json, "-jsonl", *common_speed_flags]
    else:
        cmd = [nuclei, "-l", targets_file, "-json-export", output_json, *common_speed_flags]

    return _run(cmd, "Nuclei", timeout=proc_timeout)

    return _run(cmd, "Nuclei", timeout=1200)


def parse_nuclei(json_file: str = "nuclei.jsonl") -> list[dict]:
    """
    Parse Nuclei JSONL output (one JSON object per line).
    Returns [] if file is missing or empty.
    """
    path = Path(json_file)
    if not path.exists():
        log.warning(f"[Nuclei] Output file not found: {json_file}")
        return []

    results = []
    with open(json_file, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "host":     data.get("host", "unknown"),
                    "template": data.get("template-id", "unknown"),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "name":     data.get("info", {}).get("name", "Unknown Finding"),
                    "matcher":  data.get("matcher-name", ""),
                    "url":      data.get("matched-at", ""),
                    "source":   "nuclei",
                })
            except json.JSONDecodeError as e:
                log.warning(f"[Nuclei] Skipping malformed line {line_num}: {e}")
                continue

    log.info(f"[Nuclei] Parsed {len(results)} finding(s)")
    return results


def nuclei_to_findings(nuclei_data: list[dict]) -> list[dict]:
    """Convert raw Nuclei results into the standard finding format."""
    SEV_MAP = {
        "critical": "HIGH",
        "high":     "HIGH",
        "medium":   "MEDIUM",
        "low":      "LOW",
        "info":     "INFO",
    }

    findings = []
    for item in nuclei_data:
        sev_raw  = item["severity"].lower()
        severity = SEV_MAP.get(sev_raw, "MEDIUM")
        name     = item["name"]
        template = item["template"]
        host     = item["host"]
        url      = item.get("url", host)
        matcher  = item.get("matcher", "")

        description = (
            f"Nuclei detected '{name}' on {host}. "
            f"Template: {template}"
            + (f" (matcher: {matcher})" if matcher else "")
            + f". Matched at: {url}"
        )

        findings.append({
            "id":          _generate_id(),
            "severity":    severity,
            "title":       name,
            "host":        host,
            "description": description,
            "action":      (
                "Review the Nuclei finding and apply the relevant patch or configuration fix. "
                "Consult the template documentation at https://nuclei.projectdiscovery.io "
                f"for remediation guidance on '{template}'."
            ),
            "timestamp":   _now(),
            "source":      "nuclei",
            "template":    template,
        })

    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(findings: list[dict]) -> list[dict]:
    """
    Remove duplicate findings using (host, title) as the unique key.
    When duplicates exist, keeps the highest-severity one.
    """
    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    seen: dict[tuple, dict] = {}

    for f in findings:
        key = (f.get("host", ""), f.get("title", ""))
        if key not in seen:
            seen[key] = f
        else:
            existing_rank = SEV_ORDER.get(seen[key]["severity"], 99)
            new_rank      = SEV_ORDER.get(f["severity"], 99)
            if new_rank < existing_rank:
                seen[key] = f

    deduped = list(seen.values())
    removed = len(findings) - len(deduped)
    if removed:
        log.info(f"Deduplication removed {removed} duplicate(s)")
    return deduped


# ── Combined Active Scan Runner ───────────────────────────────────────────────

def run_active_scan(
    scan_data:    list[dict],
    skip_nmap:    bool = False,
    skip_nuclei:  bool = False,
    scan_full:    bool = False,
    demo_mode:    bool = False,         # hackathon/demo: tightest timeouts, fastest settings
    targets_file: str  = "targets.txt",
    nmap_xml:     str  = "nmap.xml",
    nuclei_json:  str  = "nuclei.jsonl",
) -> list[dict]:
    """
    Run Stages 4 + 5 and return all findings.

    Speed modes (fastest → slowest):
      demo_mode=True   → Nmap 24 ports / 5s host-timeout / 60s cap
                         Nuclei 3s/template, 300 req/s, 90s cap
      default          → Nmap 24 ports / 10s host-timeout / 180s cap
                         Nuclei 5s/template, 150 req/s, 300s cap
      scan_full=True   → Nmap top-1000 + -sV / 30s host-timeout / 600s cap
                         Nuclei same as default
    """
    all_targets  = [h["host"] for h in scan_data if h.get("status", 0) != 0]
    http_targets = [h["host"] for h in scan_data if 200 <= h.get("status", 0) < 400]

    if not all_targets:
        log.warning("[Active Scan] No reachable hosts to scan.")
        return []

    write_targets(all_targets, targets_file)

    all_findings: list[dict] = []

    # ── Stage 4: Nmap ──
    if not skip_nmap:
        nmap_ok = run_nmap(targets_file, nmap_xml, scan_full=scan_full, demo_mode=demo_mode)
        if nmap_ok or Path(nmap_xml).exists():
            nmap_raw      = parse_nmap(nmap_xml)
            nmap_findings = nmap_to_findings(nmap_raw)
            all_findings.extend(nmap_findings)
            log.info(f"[Nmap] {len(nmap_findings)} finding(s) added")
        else:
            log.warning("[Nmap] Stage skipped due to errors — pipeline continues")
    else:
        log.info("[Nmap] Skipped via --no-nmap flag")

    # ── Stage 5: Nuclei (HTTP targets only) ──
    if not skip_nuclei:
        if http_targets:
            write_targets(http_targets, targets_file)
            nuclei_ok = run_nuclei(targets_file, nuclei_json, demo_mode=demo_mode)
            if nuclei_ok or Path(nuclei_json).exists():
                nuclei_raw      = parse_nuclei(nuclei_json)
                nuclei_findings = nuclei_to_findings(nuclei_raw)
                all_findings.extend(nuclei_findings)
                log.info(f"[Nuclei] {len(nuclei_findings)} finding(s) added")
            else:
                log.warning("[Nuclei] Stage skipped due to errors — pipeline continues")
        else:
            log.warning("[Nuclei] No HTTP-reachable targets — skipping")
    else:
        log.info("[Nuclei] Skipped via --no-nuclei flag")

    return all_findings