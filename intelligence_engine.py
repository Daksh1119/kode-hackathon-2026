"""
Shadow IT Discovery — Intelligence / Risk Analysis Engine
=========================================================
Member 2 Backend Module

Responsibility:
  Takes raw subdomain scan data (host + status) from Member 1,
  applies rule-based detection, and outputs structured, prioritised
  security findings a CTO can act on.

Usage:
  findings = analyze_subdomains(input_data)
"""

import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# KEYWORD RULE SETS
# Extend any list to widen detection coverage.
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
# Each entry: (title, description, action)
# ---------------------------------------------------------------------------

TEMPLATES = {
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
            "(HR, Finance, CRM, Intranet, etc.) that is reachable from the public internet. "
            "These systems commonly hold confidential data and are not designed for "
            "external access."
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
            "Unprotected API surfaces allow data extraction, abuse of business logic, "
            "and reconnaissance by attackers — even without authentication bypass."
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
            "on the public internet but access is currently blocked. The asset is still "
            "part of your attack surface and may be exploitable if access controls change "
            "or are misconfigured."
        ),
        (
            "Verify that access controls are correctly configured and will not degrade over time. "
            "Document why this service is internet-facing. "
            "Consider restricting it to internal networks if it does not need to be public."
        ),
    ),
    "unstable": (
        "Unstable Service Detected (5xx Error)",
        (
            "The subdomain '{host}' is returning server errors (5xx), indicating it is live "
            "on the internet but in an unstable state. Unstable services may leak error "
            "messages, stack traces, or internal paths that aid attackers."
        ),
        (
            "Investigate the cause of the server errors immediately. "
            "Ensure error pages do not expose stack traces or internal details. "
            "Take the service offline if it is not intentionally public."
        ),
    ),
}


# ---------------------------------------------------------------------------
# SEVERITY ORDER (for sorting output)
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
    """Human-readable label for an HTTP status code."""
    if status == 0:    return "DNS exists — HTTP unreachable"
    if status == 200:  return "Active (200 OK)"
    if status == 401:  return "Auth required (401)"
    if status == 403:  return "Access blocked (403)"
    if status >= 500:  return f"Server error ({status})"
    if status >= 300:  return f"Redirect ({status})"
    return f"HTTP {status}"


def _build_finding(template_key: str, host: str, severity: str, status: int) -> dict:
    title, desc_template, action = TEMPLATES[template_key]
    # For status 0: subdomain exists in DNS but didn't respond to HTTP probing.
    # The name-based risk classification still applies.
    extra_note = (
        " Note: this host did not respond to HTTP probing at scan time, but its "
        "DNS record exists — it may be intermittently available or firewall-gated."
    ) if status == 0 else ""
    return {
        "id": _generate_id(),
        "severity": severity,
        "title": title,
        "host": host,
        "status": status,
        "status_label": _status_label(status),
        "description": desc_template.format(host=host) + extra_note,
        "action": action,
        "timestamp": _timestamp(),
        "source": "engine",
    }


# ---------------------------------------------------------------------------
# CORE CLASSIFIER
# Applies rules in priority order: HIGH → MEDIUM → LOW → None
# ---------------------------------------------------------------------------

def classify_host(host: str, status: int) -> dict | None:
    """
    Classify a single host+status pair into a finding dict, or return None
    if the host is not considered noteworthy.

    Priority order:
      1. Admin/panel keywords          → HIGH
      2. Login/auth keywords           → HIGH
      3. Sensitive internal keywords   → HIGH
      4. Dev/staging keywords          → MEDIUM
      5. API keywords                  → MEDIUM
      6. Server errors (5xx)           → MEDIUM
      7. Restricted (403/401)          → LOW
      8. Everything else               → None (ignored)
    """

    h = host.lower()

    # --- HIGH: Admin / Management panels ---
    if any(kw in h for kw in ADMIN_KEYWORDS):
        return _build_finding("admin", host, "HIGH", status)

    # --- HIGH: Login / Auth surfaces ---
    if any(kw in h for kw in LOGIN_KEYWORDS):
        return _build_finding("login", host, "HIGH", status)

    # --- HIGH: Sensitive internal systems ---
    if any(kw in h for kw in SENSITIVE_KEYWORDS):
        return _build_finding("sensitive", host, "HIGH", status)

    # --- MEDIUM: Dev / Staging / Test ---
    if any(kw in h for kw in DEV_KEYWORDS):
        return _build_finding("dev", host, "MEDIUM", status)

    # --- MEDIUM: API endpoints ---
    if any(kw in h for kw in API_KEYWORDS):
        return _build_finding("api", host, "MEDIUM", status)

    # --- MEDIUM: Server errors (alive but broken) ---
    if status is not None and status >= 500:
        return _build_finding("unstable", host, "MEDIUM", status)

    # --- LOW: Restricted but confirmed to exist ---
    if status in (401, 403):
        return _build_finding("restricted_exists", host, "LOW", status)

    # Not noteworthy
    return None


# ---------------------------------------------------------------------------
# MAIN ANALYSIS FUNCTION
# This is the only function Member 1 / the API layer needs to call.
# ---------------------------------------------------------------------------

def analyze_subdomains(data: list[dict]) -> list[dict]:
    """
    Analyse a list of subdomain scan results and return prioritised findings.

    Args:
        data: List of dicts with at least "host" (str) and "status" (int).
              Extra keys (title, headers, protocol, etc.) are ignored safely.

    Returns:
        List of finding dicts, sorted HIGH → MEDIUM → LOW.
    """
    findings = []

    for item in data:
        host = item.get("host")
        status = item.get("status")

        if not host or not isinstance(host, str):
            continue

        # Treat missing status as unknown (still attempt classification)
        if status is None:
            status = 0

        finding = classify_host(host.strip(), int(status))
        if finding:
            findings.append(finding)

    # Sort by severity so HIGH findings appear first
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


# ---------------------------------------------------------------------------
# REPORTING HELPERS (optional — for CLI / human-readable output)
# ---------------------------------------------------------------------------

def print_report(findings: list[dict]) -> None:
    """Print a formatted report to stdout."""

    SEV_COLOUR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
    RESET = "\033[0m"
    BOLD = "\033[1m"

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
        label = f.get("status_label") or (f"HTTP {f['status']}" if "status" in f else f"Port {f.get('port', '?')}")
        print(f"    Host        : {f['host']}  ({label})")
        print(f"    Description : {f['description']}")
        print(f"    Action      : {f['action']}")
        print(f"    ID          : {f['id']}")
        print(f"    Timestamp   : {f['timestamp']}")
        print()


def findings_to_json(findings: list[dict]) -> str:
    """Return findings serialised as a JSON string (for API responses)."""
    import json
    return json.dumps(findings, indent=2)


# ---------------------------------------------------------------------------
# DEMO / QUICK TEST
# Run: python intelligence_engine.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_input = [
        {"host": "fd.somaiya.com",       "status": 200},
        {"host": "sac.somaiya.com",      "status": 200},
        {"host": "somaiya.com",          "status": 200},
        {"host": "www.sac.somaiya.com",  "status": 200},
        {"host": "www.somaiya.com",      "status": 200},
    ]

    results = analyze_subdomains(sample_input)
    print_report(results)

    # Also show raw JSON (what the API layer / Member 1 would consume)
    print("--- JSON output (first finding) ---")
    import json
    print(json.dumps(results[0], indent=2))