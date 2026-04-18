"""
Shadow IT Discovery — Intelligence / Risk Analysis Engine
=========================================================
Member 2 Backend Module

CHANGES vs original:
  - classify_host() gains optional page_info parameter
  - Page-type-confirmed findings take priority over keyword-guessed ones
    (e.g. app.company.com with a confirmed login page → HIGH, not ignored)
  - New page-type-specific templates for page-confirmed findings
  - print_report() shows page_type, page_title, and page_signals
  - findings_to_json() unchanged

Usage:
  findings = analyze_subdomains(input_data)
"""

import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# KEYWORD RULE SETS
# ---------------------------------------------------------------------------

ADMIN_KEYWORDS = [
    "admin", "administrator", "panel", "dashboard", "backend",
    "portal", "console", "manage", "mgmt", "cpanel",
    "phpmyadmin", "webmail", "sso",
]
LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "auth", "authenticate",
    "secure", "account", "accounts",
]
SENSITIVE_KEYWORDS = [
    "internal", "intranet", "private", "secret", "staff",
    "employee", "hr", "finance", "crm", "erp",
]
DEV_KEYWORDS = [
    "dev", "develop", "development",
    "staging", "stage", "preprod", "pre-prod",
    "test", "testing", "qa", "uat",
    "sandbox", "demo", "beta", "preview",
    "canary", "temp", "old", "legacy", "backup", "bak",
]
API_KEYWORDS = [
    "api", "api-dev", "api-staging", "graphql", "rest",
]


# ---------------------------------------------------------------------------
# FINDING TEMPLATES
# ---------------------------------------------------------------------------

TEMPLATES = {
    # ── Keyword-based templates (original) ────────────────────────────────────
    "admin": (
        "Public Admin Panel Detected",
        (
            "The subdomain '{host}' exposes an administrative interface on the public "
            "internet. Admin panels provide access to backend controls, user management, "
            "and system configuration — they should never be reachable without strict "
            "access controls."
        ),
        (
            "Immediately restrict access behind a VPN or IP allowlist. "
            "Require MFA for all admin logins. "
            "Consider moving the admin interface off a public subdomain entirely."
        ),
    ),
    "login": (
        "Login Interface Publicly Reachable",
        (
            "The subdomain '{host}' exposes a login or authentication page to the internet. "
            "Public login surfaces are direct targets for brute-force and credential-stuffing "
            "attacks, especially if rate-limiting or MFA is not enforced."
        ),
        (
            "Enable MFA on all accounts accessible via this login page. "
            "Implement rate-limiting and account lockout policies. "
            "Ensure the underlying system is patched to the latest version."
        ),
    ),
    "sensitive": (
        "Sensitive Internal System Exposed",
        (
            "The subdomain '{host}' suggests an internal or sensitive business system "
            "(HR, Finance, CRM, Intranet, etc.) that is reachable from the public internet."
        ),
        (
            "Restrict access to internal networks or VPN immediately. "
            "Audit current access logs to check for any unauthorised access. "
            "Review whether this system needs to be internet-facing at all."
        ),
    ),
    "dev": (
        "Non-Production Environment Publicly Reachable",
        (
            "The subdomain '{host}' appears to be a development, staging, or test environment "
            "accessible from the internet. Non-production environments typically run older code, "
            "weaker security configurations, and may contain test credentials or real data "
            "copied from production."
        ),
        (
            "Move this environment behind VPN or an IP allowlist. "
            "Remove any test/default credentials. "
            "Ensure no real customer or production data is present in this environment."
        ),
    ),
    "api": (
        "API Endpoint Publicly Exposed",
        (
            "The subdomain '{host}' exposes an API endpoint to the public internet. "
            "Unprotected API surfaces allow data extraction and abuse of business logic."
        ),
        (
            "Verify that authentication is required on all API routes. "
            "Add rate-limiting and request logging. "
            "Remove or gate any debug or internal-only endpoints."
        ),
    ),
    "restricted_exists": (
        "Restricted Endpoint Detected (Access Blocked)",
        (
            "The subdomain '{host}' returned HTTP 403/401, meaning the service exists "
            "on the public internet but access is currently blocked. It is still part of "
            "your attack surface."
        ),
        (
            "Verify that access controls are correctly configured and will not degrade over time. "
            "Consider restricting it to internal networks if it does not need to be public."
        ),
    ),
    "unstable": (
        "Unstable Service Detected (5xx Error)",
        (
            "The subdomain '{host}' is returning server errors (5xx). Unstable services "
            "may leak error messages, stack traces, or internal paths that aid attackers."
        ),
        (
            "Investigate the cause of the server errors immediately. "
            "Ensure error pages do not expose stack traces or internal details."
        ),
    ),

    # ── Page-classifier-confirmed templates ───────────────────────────────────
    # Used when the page classifier catches something the subdomain name missed.
    "page_login": (
        "Login Page Confirmed on Public Subdomain",
        (
            "The subdomain '{host}' was confirmed by page analysis to serve a login page, "
            "even though its name gave no indication of this. This login surface is publicly "
            "reachable and is a target for brute-force and credential-stuffing attacks."
        ),
        (
            "Enable MFA on all accounts accessible via this page. "
            "Enforce rate-limiting and account lockout. "
            "Verify the page is intentionally public-facing."
        ),
    ),
    "page_admin": (
        "Admin Panel Confirmed on Public Subdomain",
        (
            "Page content analysis confirmed that '{host}' serves an admin or management "
            "interface, despite not having an obviously admin-related subdomain name. "
            "This may have been overlooked in previous security reviews."
        ),
        (
            "Restrict access immediately behind VPN or IP allowlist. "
            "Require MFA. Investigate how this became publicly accessible."
        ),
    ),
    "page_database_ui": (
        "Database Management UI Publicly Exposed",
        (
            "A database management interface (such as phpMyAdmin, Adminer, or pgAdmin) was "
            "confirmed at '{host}'. These tools provide direct access to your database and are "
            "among the most critical assets that can be exposed to the internet."
        ),
        (
            "Take this offline from the public internet immediately. "
            "Restrict access to localhost or internal VPN only. "
            "Rotate all database credentials and audit access logs."
        ),
    ),
    "page_file_listing": (
        "Directory Listing Exposed — Files Publicly Browsable",
        (
            "The web server at '{host}' has directory listing enabled. Anyone can browse "
            "its files like a file manager, exposing source code, config files, and backups."
        ),
        (
            "Disable directory listing in your web server configuration immediately. "
            "Audit the exposed directory for sensitive files (credentials, configs, backups). "
            "Rotate any credentials found."
        ),
    ),
    "page_ci_cd": (
        "CI/CD Interface Publicly Accessible",
        (
            "A CI/CD tool (Jenkins, GitLab, TeamCity, etc.) was confirmed at '{host}'. "
            "CI/CD systems hold source code, secrets, and deployment pipelines — they must "
            "never be reachable from the public internet without strong access controls."
        ),
        (
            "Restrict this interface to internal network or VPN immediately. "
            "Rotate all pipeline secrets and API tokens. "
            "Audit recent pipeline runs for unauthorised access."
        ),
    ),
    "page_api": (
        "API Endpoint Confirmed on Public Subdomain",
        (
            "Page content analysis confirmed that '{host}' serves an API endpoint, despite "
            "its name not indicating this. Exposed APIs allow data extraction and abuse of "
            "business logic even without authentication bypass."
        ),
        (
            "Ensure all API routes require authentication. "
            "Add rate-limiting and request logging. "
            "Remove or protect any debug or internal-only endpoints."
        ),
    ),
    "page_monitoring": (
        "Monitoring Interface Publicly Reachable",
        (
            "A monitoring dashboard (Grafana, Kibana, Prometheus, etc.) was detected at "
            "'{host}'. These expose infrastructure metrics, logs, and system internals — "
            "valuable reconnaissance data for an attacker."
        ),
        (
            "Restrict access to internal network or VPN. "
            "Enable authentication if not already required. "
            "Review what data is visible to an unauthenticated visitor."
        ),
    ),
}


# ---------------------------------------------------------------------------
# PAGE TYPE → TEMPLATE + SEVERITY MAPPING
# Only page types that should generate their own finding are listed here.
# Others fall through to status-based rules.
# ---------------------------------------------------------------------------

PAGE_TYPE_TEMPLATE = {
    "login":        ("page_login",        "HIGH"),
    "admin_panel":  ("page_admin",        "HIGH"),
    "database_ui":  ("page_database_ui",  "HIGH"),
    "file_listing": ("page_file_listing", "HIGH"),
    "ci_cd":        ("page_ci_cd",        "HIGH"),
    "api_json":     ("page_api",          "MEDIUM"),
    "api_docs":     ("page_api",          "MEDIUM"),
    "monitoring":   ("page_monitoring",   "MEDIUM"),
}


# ---------------------------------------------------------------------------
# SEVERITY ORDER
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _generate_id() -> str:
    return str(uuid.uuid4())

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

def _status_label(status: int) -> str:
    if status == 0:    return "DNS exists — HTTP unreachable"
    if status == 200:  return "Active (200 OK)"
    if status == 401:  return "Auth required (401)"
    if status == 403:  return "Access blocked (403)"
    if status >= 500:  return f"Server error ({status})"
    if status >= 300:  return f"Redirect ({status})"
    return f"HTTP {status}"

def _build_finding(
    template_key: str,
    host:         str,
    severity:     str,
    status:       int,
    page_type:    str       = "",
    page_title:   str       = "",
    page_signals: list      = None,
) -> dict:
    title, desc_template, action = TEMPLATES[template_key]
    extra_note = (
        " Note: this host did not respond to HTTP probing at scan time, but its "
        "DNS record exists — it may be intermittently available or firewall-gated."
    ) if status == 0 else ""

    finding = {
        "id":           _generate_id(),
        "severity":     severity,
        "title":        title,
        "host":         host,
        "status":       status,
        "status_label": _status_label(status),
        "description":  desc_template.format(host=host) + extra_note,
        "action":       action,
        "timestamp":    _timestamp(),
        "source":       "engine",
    }
    if page_type:
        finding["page_type"]    = page_type
        finding["page_title"]   = page_title
        finding["page_signals"] = page_signals or []
    return finding

def _sev_rank(f: dict) -> int:
    return SEVERITY_ORDER.get(f.get("severity", "INFO"), 99)


# ---------------------------------------------------------------------------
# CORE CLASSIFIER
# ---------------------------------------------------------------------------

def classify_host(
    host:      str,
    status:    int,
    page_info: dict | None = None,
) -> dict | None:
    """
    Classify a single host into a finding dict, or return None.

    Args:
        host:      Hostname string.
        status:    HTTP status from status_prober (0 = unreachable).
        page_info: Optional dict from page_classifier:
                     {page_type, page_title, page_signals}
                   Page-confirmed findings take priority over keyword guesses.

    Priority order (highest first):
      1. Page-type HIGH  (login, admin_panel, database_ui, file_listing, ci_cd)
      2. Keyword HIGH    (admin/login/sensitive in subdomain name)
      3. Page-type MEDIUM (api, monitoring)
      4. Keyword MEDIUM  (dev/api in subdomain name)
      5. Status-based    (5xx → MEDIUM, 401/403 → LOW)
      6. None            (nothing noteworthy)
    """
    h = host.lower()

    page_type    = (page_info or {}).get("page_type",    "")
    page_title   = (page_info or {}).get("page_title",   "")
    page_signals = (page_info or {}).get("page_signals", [])

    # ── Keyword-based finding ─────────────────────────────────────────────────
    keyword_finding = None
    if any(kw in h for kw in ADMIN_KEYWORDS):
        keyword_finding = _build_finding("admin", host, "HIGH", status)
    elif any(kw in h for kw in LOGIN_KEYWORDS):
        keyword_finding = _build_finding("login", host, "HIGH", status)
    elif any(kw in h for kw in SENSITIVE_KEYWORDS):
        keyword_finding = _build_finding("sensitive", host, "HIGH", status)
    elif any(kw in h for kw in DEV_KEYWORDS):
        keyword_finding = _build_finding("dev", host, "MEDIUM", status)
    elif any(kw in h for kw in API_KEYWORDS):
        keyword_finding = _build_finding("api", host, "MEDIUM", status)
    elif status >= 500:
        keyword_finding = _build_finding("unstable", host, "MEDIUM", status)
    elif status in (401, 403):
        keyword_finding = _build_finding("restricted_exists", host, "LOW", status)

    # ── Page-type-based finding ───────────────────────────────────────────────
    page_finding = None
    if page_type and page_type in PAGE_TYPE_TEMPLATE:
        tmpl_key, page_sev = PAGE_TYPE_TEMPLATE[page_type]
        page_finding = _build_finding(
            tmpl_key, host, page_sev, status,
            page_type=page_type, page_title=page_title, page_signals=page_signals,
        )

    # ── Merge: pick highest-severity, prefer page_finding on tie ─────────────
    if keyword_finding and page_finding:
        if _sev_rank(page_finding) <= _sev_rank(keyword_finding):
            best = page_finding
        else:
            best = keyword_finding
            best["page_type"]    = page_type
            best["page_title"]   = page_title
            best["page_signals"] = page_signals
        return best

    if page_finding:
        return page_finding    # page classifier caught something the name missed

    if keyword_finding:
        if page_type:          # enrich keyword finding with page info
            keyword_finding["page_type"]    = page_type
            keyword_finding["page_title"]   = page_title
            keyword_finding["page_signals"] = page_signals
        return keyword_finding

    return None


# ---------------------------------------------------------------------------
# MAIN ANALYSIS FUNCTION
# ---------------------------------------------------------------------------

def analyze_subdomains(data: list[dict]) -> list[dict]:
    """
    Analyse a list of subdomain scan results and return prioritised findings.

    Args:
        data: List of dicts with at least "host" (str) and "status" (int).
              Optionally also "page_type", "page_title", "page_signals"
              (added by page_classifier.classify_pages in Stage 3).

    Returns:
        List of finding dicts, sorted HIGH → MEDIUM → LOW.
    """
    findings = []
    for item in data:
        host   = item.get("host")
        status = item.get("status")

        if not host or not isinstance(host, str):
            continue
        if status is None:
            status = 0

        page_info = None
        if item.get("page_type"):
            page_info = {
                "page_type":    item.get("page_type",    "unknown"),
                "page_title":   item.get("page_title",   ""),
                "page_signals": item.get("page_signals", []),
            }

        finding = classify_host(host.strip(), int(status), page_info)
        if finding:
            findings.append(finding)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


# ---------------------------------------------------------------------------
# REPORTING HELPERS
# ---------------------------------------------------------------------------

def print_report(findings: list[dict]) -> None:
    """Print a formatted, human-readable report to stdout."""

    SEV_COLOUR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    CYAN  = "\033[96m"

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  ATTACK SURFACE INTELLIGENCE REPORT{RESET}")
    print(f"{'='*60}")
    print(f"  Total findings : {len(findings)}")
    print(f"  HIGH           : {SEV_COLOUR['HIGH']}{counts['HIGH']}{RESET}")
    print(f"  MEDIUM         : {SEV_COLOUR['MEDIUM']}{counts['MEDIUM']}{RESET}")
    print(f"  LOW            : {SEV_COLOUR['LOW']}{counts['LOW']}{RESET}")
    print(f"{'='*60}\n")

    for i, f in enumerate(findings, 1):
        colour = SEV_COLOUR.get(f["severity"], "")
        print(f"{BOLD}[{i}] {colour}{f['severity']}{RESET}{BOLD} — {f['title']}{RESET}")

        # Host + status/port line
        if "status_label" in f:
            print(f"    Host      : {f['host']}  ({f['status_label']})")
        elif "port" in f:
            print(f"    Host      : {f['host']}  (port {f['port']})")
        else:
            print(f"    Host      : {f['host']}")

        # Page classification line (shown only when confirmed)
        page_type = f.get("page_type", "")
        if page_type and page_type not in ("unknown", ""):
            # Import label from page_classifier; fall back gracefully if module not loaded
            try:
                from page_classifier import PAGE_TYPE_META
                label = PAGE_TYPE_META.get(page_type, (page_type.replace("_", " ").title(), ""))[0]
            except ImportError:
                label = page_type.replace("_", " ").title()

            title_str = f'  ("{f["page_title"]}")' if f.get("page_title") else ""
            print(f"    {CYAN}Page Type {RESET}: {label}{title_str}")

            signals = f.get("page_signals", [])
            if signals:
                print(f"    {DIM}Signals   : {'; '.join(signals)}{RESET}")

        print(f"    Why       : {f['description']}")
        print(f"    Fix       : {f['action']}")
        print(f"    ID        : {f['id']}")
        print()


def findings_to_json(findings: list[dict]) -> str:
    """Return findings serialised as a JSON string."""
    import json
    return json.dumps(findings, indent=2)


# ---------------------------------------------------------------------------
# DEMO / QUICK TEST  —  python intelligence_engine.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_input = [
        # keyword AND page confirm admin
        {"host": "admin.somaiya.com",  "status": 200,
         "page_type": "admin_panel",  "page_title": "Site Administration",
         "page_signals": ["page title contains 'administration'"]},
        # NO keyword match, but page classifier found a login page
        {"host": "app.somaiya.com",    "status": 200,
         "page_type": "login",         "page_title": "Sign In — Staff Portal",
         "page_signals": ["password input field found", "title contains 'sign in'"]},
        # directory listing — HIGH regardless of name
        {"host": "files.somaiya.com",  "status": 200,
         "page_type": "file_listing",  "page_title": "Index of /uploads",
         "page_signals": ["directory listing title detected"]},
        # dev subdomain — keyword catch, enriched with page info
        {"host": "dev.somaiya.com",    "status": 200,
         "page_type": "web_app",       "page_title": "Development Build",  "page_signals": []},
        # generic subdomain, no page info → no finding (200 but nothing suspicious)
        {"host": "www.somaiya.com",    "status": 200},
    ]

    results = analyze_subdomains(sample_input)
    print_report(results)
    print("--- JSON (first finding) ---")
    import json
    if results:
        print(json.dumps(results[0], indent=2))