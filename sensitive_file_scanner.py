"""
Sensitive File & Backup Exposure Scanner — Stage 8
====================================================
For every live subdomain discovered by the pipeline, this module:

  Layer 1 — HTTP probe (parallel)
    GETs a comprehensive list of known-sensitive paths.
    Any path returning HTTP 200 is flagged.

  Layer 2 — Content inspection
    For every 200 response, reads the first 8 KB and checks for
    real secret keywords (DB passwords, AWS keys, private keys, etc.)
    drawn from nuclei_sensitive_files.yaml.
    Content matches upgrade severity and add an `exposed_secrets` list.

  Layer 3 — Nuclei template (optional)
    If nuclei is installed AND nuclei_sensitive_files.yaml is present
    beside this file, nuclei is run with that template for confirmation.
    Results are merged and deduplicated by (host, path).

Output: list of standard pipeline finding dicts
  {id, severity, title, host, description, action, source, timestamp}
  plus extra fields: exposed_url, file_path, exposed_secrets (if any)

Usage (called by pipeline.py):
  from sensitive_file_scanner import scan_sensitive_files
  findings = scan_sensitive_files(scan_data, nuclei_exe=NUCLEI_PATH)
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

log = logging.getLogger("sensitive_file_scanner")

TIMEOUT     = 6      # seconds per HTTP request
MAX_WORKERS = 30     # concurrent probes
BODY_LIMIT  = 8192   # bytes to read for content inspection


# ── Comprehensive sensitive path list ────────────────────────────────────────
# Each entry: (path, description, base_severity)
# base_severity is upgraded to HIGH if content secrets are found.

SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # ── Secrets / credentials ─────────────────────────────────────────────────
    ("/.env",                     "Environment variables file",           "HIGH"),
    ("/.env.local",               "Local environment override file",      "HIGH"),
    ("/.env.production",          "Production environment file",          "HIGH"),
    ("/.env.backup",              "Environment file backup",              "HIGH"),
    ("/.env.bak",                 "Environment file backup (.bak)",       "HIGH"),
    ("/.env.old",                 "Old environment file",                 "HIGH"),
    ("/.env.example",             "Example environment file (may have real values)", "MEDIUM"),
    ("/.aws/credentials",         "AWS credentials file",                 "HIGH"),
    ("/.aws/config",              "AWS config file",                      "MEDIUM"),
    ("/.npmrc",                   "npm auth tokens file",                 "HIGH"),
    ("/credentials.json",         "Service account credentials",          "HIGH"),
    ("/service-account.json",     "GCP service account key",              "HIGH"),
    ("/secret.json",              "Secret configuration file",            "HIGH"),
    ("/secrets.json",             "Secrets configuration file",           "HIGH"),
    ("/id_rsa",                   "SSH private key",                      "HIGH"),
    ("/id_rsa.pub",               "SSH public key",                       "LOW"),
    ("/id_ed25519",               "SSH Ed25519 private key",              "HIGH"),
    ("/private.key",              "Private key file",                     "HIGH"),
    ("/server.key",               "Server private key",                   "HIGH"),
    ("/private.pem",              "PEM private key",                      "HIGH"),
    ("/.htpasswd",                "Apache password file",                 "HIGH"),

    # ── App configuration ─────────────────────────────────────────────────────
    ("/config.php",               "PHP application config",               "HIGH"),
    ("/wp-config.php",            "WordPress database credentials",       "HIGH"),
    ("/wp-config.php.bak",        "WordPress config backup",              "HIGH"),
    ("/web.config",               "IIS/ASP.NET configuration",            "HIGH"),
    ("/appsettings.json",         "ASP.NET application settings",         "HIGH"),
    ("/appsettings.Production.json", "ASP.NET production settings",       "HIGH"),
    ("/config.json",              "Application configuration",            "MEDIUM"),
    ("/config.yaml",              "YAML configuration file",              "MEDIUM"),
    ("/config.yml",               "YAML configuration file",              "MEDIUM"),
    ("/database.yml",             "Database connection config",           "HIGH"),
    ("/database.yaml",            "Database connection config",           "HIGH"),
    ("/settings.py",              "Django settings file",                 "HIGH"),
    ("/local_settings.py",        "Django local settings",                "HIGH"),
    ("/application.properties",   "Spring Boot properties",               "HIGH"),
    ("/application.yml",          "Spring Boot YAML config",              "HIGH"),
    ("/.htaccess",                "Apache access configuration",          "MEDIUM"),
    ("/php.ini",                  "PHP configuration file",               "MEDIUM"),
    ("/configuration.php",        "CMS configuration file",               "HIGH"),
    ("/config/database.php",      "Laravel database config",              "HIGH"),
    ("/config/app.php",           "Laravel app config",                   "MEDIUM"),

    # ── Version control ───────────────────────────────────────────────────────
    ("/.git/config",              "Git repository configuration",         "HIGH"),
    ("/.git/HEAD",                "Git HEAD reference (repo exposed)",    "HIGH"),
    ("/.git/COMMIT_EDITMSG",      "Git last commit message",              "MEDIUM"),
    ("/.git/index",               "Git index file",                       "MEDIUM"),
    ("/.svn/entries",             "SVN repository entries",               "HIGH"),
    ("/.svn/wc.db",               "SVN working copy database",            "HIGH"),
    ("/.hg/hgrc",                 "Mercurial repository config",          "HIGH"),

    # ── Database backups ──────────────────────────────────────────────────────
    ("/backup.sql",               "Database backup dump",                 "HIGH"),
    ("/dump.sql",                 "Database dump",                        "HIGH"),
    ("/database.sql",             "Full database export",                 "HIGH"),
    ("/db.sql",                   "Database SQL file",                    "HIGH"),
    ("/site.sql",                 "Site database dump",                   "HIGH"),
    ("/db.dump",                  "Database dump file",                   "HIGH"),
    ("/database.backup",          "Database backup file",                 "HIGH"),

    # ── Archive backups ───────────────────────────────────────────────────────
    ("/backup.zip",               "Site backup archive (.zip)",           "HIGH"),
    ("/backup.tar.gz",            "Site backup archive (.tar.gz)",        "HIGH"),
    ("/backup.tgz",               "Site backup archive (.tgz)",           "HIGH"),
    ("/backup.bak",               "Backup file (.bak)",                   "HIGH"),
    ("/backup.old",               "Old backup file",                      "MEDIUM"),
    ("/site.backup",              "Full site backup",                     "HIGH"),
    ("/www.zip",                  "Web root archive",                     "HIGH"),
    ("/html.zip",                 "HTML directory archive",               "HIGH"),
    ("/public.zip",               "Public directory archive",             "HIGH"),

    # ── Log files ─────────────────────────────────────────────────────────────
    ("/debug.log",                "Debug log file",                       "MEDIUM"),
    ("/error.log",                "Error log file",                       "MEDIUM"),
    ("/access.log",               "HTTP access log",                      "MEDIUM"),
    ("/app.log",                  "Application log",                      "MEDIUM"),
    ("/laravel.log",              "Laravel application log",              "MEDIUM"),
    ("/storage/logs/laravel.log", "Laravel log (storage path)",           "MEDIUM"),

    # ── Infrastructure / DevOps ───────────────────────────────────────────────
    ("/docker-compose.yml",       "Docker Compose configuration",         "MEDIUM"),
    ("/docker-compose.yaml",      "Docker Compose configuration",         "MEDIUM"),
    ("/Dockerfile",               "Docker build file",                    "LOW"),
    ("/.dockerenv",               "Docker environment marker",            "LOW"),
    ("/Jenkinsfile",              "Jenkins pipeline definition",          "MEDIUM"),
    ("/.github/workflows/deploy.yml", "GitHub Actions deploy workflow",  "MEDIUM"),
    ("/terraform.tfvars",         "Terraform variables (may have secrets)","HIGH"),
    ("/terraform.tfstate",        "Terraform state file",                 "HIGH"),
    ("/.terraform/terraform.tfstate", "Terraform state (hidden dir)",    "HIGH"),

    # ── Package / dependency files ────────────────────────────────────────────
    ("/package.json",             "Node.js package manifest",             "LOW"),
    ("/package-lock.json",        "Node.js lock file",                    "LOW"),
    ("/composer.json",            "PHP Composer manifest",                "LOW"),
    ("/requirements.txt",         "Python dependencies list",             "LOW"),
    ("/Gemfile",                  "Ruby Gemfile",                         "LOW"),
    ("/yarn.lock",                "Yarn lock file",                       "LOW"),

    # ── Info / debug pages ────────────────────────────────────────────────────
    ("/phpinfo.php",              "PHP info page (server info leak)",     "MEDIUM"),
    ("/info.php",                 "PHP info page (alternate name)",       "MEDIUM"),
    ("/server-status",            "Apache server-status page",            "MEDIUM"),
    ("/server-info",              "Apache server-info page",              "MEDIUM"),
    ("/elmah.axd",                "ASP.NET error log viewer",             "HIGH"),
    ("/trace.axd",                "ASP.NET trace viewer",                 "HIGH"),
    ("/_profiler",                "Symfony profiler",                     "MEDIUM"),
    ("/__debug_toolbar__",        "Django debug toolbar",                 "MEDIUM"),
    ("/actuator",                 "Spring Boot actuator (root)",          "HIGH"),
    ("/actuator/env",             "Spring Boot actuator env endpoint",    "HIGH"),
    ("/actuator/heapdump",        "Spring Boot heap dump",                "HIGH"),
    ("/health",                   "Health check endpoint",                "LOW"),
    ("/metrics",                  "Metrics endpoint",                     "LOW"),

    # ── Misc known leaks ──────────────────────────────────────────────────────
    ("/crossdomain.xml",          "Flash cross-domain policy",            "LOW"),
    ("/clientaccesspolicy.xml",   "Silverlight cross-domain policy",      "LOW"),
    ("/robots.txt",               "Robots exclusion file (info only)",    "LOW"),
    ("/sitemap.xml",              "Sitemap (path enumeration)",           "LOW"),
    ("/CHANGELOG.md",             "Changelog (version disclosure)",       "LOW"),
    ("/CHANGELOG",                "Changelog (version disclosure)",       "LOW"),
    ("/README.md",                "README file",                          "LOW"),
    ("/LICENSE",                  "License file",                         "LOW"),
]


# ── Secret keyword groups (from nuclei_sensitive_files.yaml matchers) ────────
# Each entry: (group_label, [keywords])
# If any keyword in a group is found in the body the file is confirmed to
# contain real secrets and severity is forced to HIGH.

SECRET_KEYWORD_GROUPS: list[tuple[str, list[str]]] = [
    ("Database credentials", [
        "DB_PASSWORD", "DB_NAME", "DB_USER", "DATABASE_URL",
        "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD",
        "spring.datasource", "connectionStrings",
    ]),
    ("AWS / cloud keys", [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
    ]),
    ("App secrets", [
        "APP_KEY", "APP_SECRET", "SECRET_KEY", "DJANGO_SECRET_KEY",
        "RAILS_MASTER_KEY", "JWT_SECRET",
    ]),
    ("Auth tokens", [
        "MAIL_PASSWORD", "REDIS_PASSWORD", "token=", "_authToken",
        "password=", "secret=", "client_secret",
    ]),
    ("Private keys", [
        "PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY",
    ]),
    ("Service account", [
        "service_account", "\"type\": \"service_account\"",
    ]),
    ("Git repo markers", [
        "[core]", "repositoryformatversion", "ref: refs/heads",
    ]),
    ("Database dumps", [
        "CREATE TABLE", "INSERT INTO", "mysqldump", "pg_dump",
        "dump completed",
    ]),
    ("IIS/ASP.NET config", [
        "<configuration>", "<?xml", "connectionStrings",
    ]),
    ("PHP config", [
        "<?php", "AuthUserFile",
    ]),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _id() -> str:
    return str(uuid.uuid4())

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

def _sev_rank(s: str) -> int:
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s.upper(), 3)


def _probe_path(host: str, path: str) -> tuple[int | None, str]:
    """
    GET https://{host}{path}, fall back to http.
    Returns (status_code, body_snippet).
    body_snippet is empty string if status != 200.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        req = Request(url, method="GET",
                      headers={"User-Agent": "shadow-it-file-scanner/1.0",
                                "Accept": "*/*"})
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                status = int(getattr(resp, "status", 0) or 0)
                body   = resp.read(BODY_LIMIT).decode("utf-8", errors="replace") if status == 200 else ""
                return status, body
        except HTTPError as e:
            return int(e.code), ""
        except (URLError, socket.timeout, ConnectionRefusedError, OSError):
            continue
    return None, ""


def _inspect_content(body: str) -> list[str]:
    """
    Scan body for secret keywords.
    Returns list of matched group labels (e.g. ["Database credentials", "AWS / cloud keys"]).
    """
    matched = []
    body_upper = body.upper()
    for label, keywords in SECRET_KEYWORD_GROUPS:
        if any(kw.upper() in body_upper for kw in keywords):
            matched.append(label)
    return matched


def _build_finding(
    host:        str,
    path:        str,
    desc:        str,
    severity:    str,
    url:         str,
    secrets:     list[str],
) -> dict:
    confirmed_msg = ""
    if secrets:
        confirmed_msg = (
            f" Content inspection confirmed real secrets in this file: "
            f"{', '.join(secrets)}."
        )
        severity = "HIGH"   # always HIGH if secrets confirmed

    return {
        "id":             _id(),
        "severity":       severity,
        "title":          f"Sensitive File Exposed — {path.lstrip('/')}",
        "host":           host,
        "exposed_url":    url,
        "file_path":      path,
        "description":    (
            f"The file '{path}' ({desc}) is publicly accessible at {url}."
            + confirmed_msg
        ),
        "action":         (
            "Remove or restrict access to this file immediately. "
            + ("Rotate all secrets, credentials and tokens found in the file. " if secrets else "")
            + "Ensure your web server does not serve sensitive files (add deny rules for these paths). "
            "Audit your deployment pipeline to prevent future leaks."
        ),
        "exposed_secrets": secrets,
        "timestamp":      _ts(),
        "source":         "file_scanner",
    }


# ── Per-host scanner ──────────────────────────────────────────────────────────

def _scan_host(host: str) -> list[dict]:
    """Probe all sensitive paths on a single host and return findings."""
    findings = []
    for path, desc, base_sev in SENSITIVE_PATHS:
        status, body = _probe_path(host, path)
        if status == 200:
            url = f"https://{host}{path}"
            secrets = _inspect_content(body) if body else []
            finding = _build_finding(host, path, desc, base_sev, url, secrets)
            findings.append(finding)
            secret_tag = f"  ⚠ secrets: {', '.join(secrets)}" if secrets else ""
            log.debug(f"[{host}] FOUND {path} ({base_sev}){secret_tag}")
    return findings


# ── Nuclei template runner (optional) ────────────────────────────────────────

def _run_nuclei_template(
    http_hosts:    list[str],
    nuclei_exe:    str,
    template_path: str,
    output_file:   str = "nuclei_sensitive.jsonl",
) -> list[dict]:
    """
    Run nuclei with nuclei_sensitive_files.yaml against http_hosts.
    Returns list of raw nuclei result dicts (host, path, matched_keywords).
    Returns [] if nuclei is not available or the template is missing.
    """
    if not nuclei_exe or not Path(template_path).exists():
        return []

    # Write targets
    targets_file = "targets_sensitive.txt"
    Path(targets_file).write_text(
        "\n".join(f"https://{h}" for h in http_hosts), encoding="utf-8"
    )

    cmd = [
        nuclei_exe,
        "-l",        targets_file,
        "-t",        template_path,
        "-o",        output_file,
        "-jsonl",
        "-no-interactsh",
        "-timeout",  "5",
        "-rate-limit", "100",
        "-silent",
        "-nc",
    ]

    log.info(f"[Nuclei] Running template: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            log.warning(f"[Nuclei template] Exited {result.returncode}")
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        log.warning(f"[Nuclei template] Failed: {e}")
        return []

    # Parse JSONL output
    out_path = Path(output_file)
    if not out_path.exists():
        return []

    results = []
    with open(output_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "host":     data.get("host", ""),
                    "path":     data.get("matched-at", ""),
                    "template": data.get("template-id", ""),
                    "severity": data.get("info", {}).get("severity", "high"),
                    "name":     data.get("info", {}).get("name", ""),
                    "matcher":  data.get("matcher-name", ""),
                })
            except json.JSONDecodeError:
                continue
    log.info(f"[Nuclei template] Parsed {len(results)} result(s)")
    return results


def _nuclei_to_findings(nuclei_results: list[dict]) -> list[dict]:
    """Convert raw nuclei template results to pipeline finding format."""
    SEV_MAP = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM",
               "low": "LOW", "info": "LOW"}
    findings = []
    for item in nuclei_results:
        matched_at = item.get("path", "")
        host       = item.get("host", "")
        # Extract path from matched_at URL
        try:
            from urllib.parse import urlparse as _up
            path = _up(matched_at).path or matched_at
        except Exception:
            path = matched_at

        findings.append({
            "id":             _id(),
            "severity":       SEV_MAP.get(item.get("severity", "high").lower(), "HIGH"),
            "title":          f"Sensitive File Confirmed by Nuclei — {Path(path).name}",
            "host":           host,
            "exposed_url":    matched_at,
            "file_path":      path,
            "description":    (
                f"Nuclei template '{item.get('template')}' confirmed that "
                f"'{path}' at {matched_at} is accessible and contains "
                f"sensitive content (matcher: {item.get('matcher', 'n/a')})."
            ),
            "action":         (
                "Remove or restrict access to this file immediately. "
                "Rotate any secrets or credentials it contains. "
                "Audit your deployment pipeline to prevent future leaks."
            ),
            "exposed_secrets": [item.get("matcher", "")] if item.get("matcher") else [],
            "timestamp":      _ts(),
            "source":         "file_scanner",
        })
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_sensitive_files(
    scan_data:     list[dict],
    nuclei_exe:    str  = "",
    template_path: str  = "",
    max_workers:   int  = MAX_WORKERS,
) -> list[dict]:
    """
    Scan every live subdomain for exposed sensitive files.

    Args:
        scan_data:     Output of status_prober — list of {host, status}.
        nuclei_exe:    Path to nuclei binary (optional).  If provided and
                       nuclei_sensitive_files.yaml exists, nuclei is also run.
        template_path: Path to nuclei_sensitive_files.yaml.  Defaults to
                       the same directory as this file.
        max_workers:   Thread-pool size for HTTP probes (default 30).

    Returns:
        List of standard pipeline finding dicts, deduplicated by (host, path),
        highest severity wins on duplicates.
    """
    # Resolve template path
    if not template_path:
        template_path = str(Path(__file__).parent / "nuclei_sensitive_files.yaml")

    # Only probe hosts that are actually live (status != 0)
    live = [h["host"] for h in scan_data if 200 <= h.get("status", 0) < 500]
    if not live:
        log.info("[File Scanner] No live hosts to scan.")
        return []

    log.info(f"[File Scanner] Probing {len(live)} host(s) × "
             f"{len(SENSITIVE_PATHS)} paths = "
             f"{len(live) * len(SENSITIVE_PATHS)} total requests...")

    # ── Layer 1 + 2: HTTP probe + content inspection ─────────────────────────
    all_findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_host, host): host for host in live}
        done = 0
        for future in as_completed(futures):
            host_findings = future.result()
            all_findings.extend(host_findings)
            done += 1
            if done % 5 == 0 or done == len(live):
                log.info(f"  [File Scanner] Scanned {done}/{len(live)} hosts, "
                         f"{len(all_findings)} finding(s) so far...")

    # ── Layer 3: Nuclei template (optional) ──────────────────────────────────
    nuclei_findings: list[dict] = []
    if nuclei_exe:
        http_live = [h["host"] for h in scan_data if 200 <= h.get("status", 0) < 400]
        nuclei_raw      = _run_nuclei_template(http_live, nuclei_exe, template_path)
        nuclei_findings = _nuclei_to_findings(nuclei_raw)
        log.info(f"[File Scanner] Nuclei template: {len(nuclei_findings)} finding(s)")

    combined = all_findings + nuclei_findings

    # ── Deduplicate by (host, file_path): keep highest severity ──────────────
    seen: dict[tuple, dict] = {}
    for f in combined:
        key = (f.get("host", ""), f.get("file_path", ""))
        if key not in seen or _sev_rank(f["severity"]) < _sev_rank(seen[key]["severity"]):
            seen[key] = f

    deduped = sorted(seen.values(), key=lambda f: _sev_rank(f["severity"]))
    log.info(f"[File Scanner] {len(deduped)} unique finding(s) after dedup.")
    return deduped
