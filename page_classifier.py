"""
Page Classifier — Stage 3
==========================
Fetches the actual content of each live host and identifies what kind of
page or service it is. This bridges the gap between "a hostname exists"
and "here is what it actually exposes".

Without this stage, the pipeline can only guess based on subdomain names
(e.g. "admin" in the hostname). With it, a host like app.company.com that
turns out to serve a login form gets classified as HIGH risk even though
its name gave nothing away.

Identified page types and their default severity:
  HIGH   → login, admin_panel, database_ui, file_listing, ci_cd
  MEDIUM → api_json, api_docs, monitoring, dashboard
  LOW    → docs, staging, error_page, web_app
  (none) → static_site, unknown  (status-code rules still apply)

Usage (called by pipeline.py):
  enriched = classify_pages(probed_hosts)
  # Each item gains: page_type, page_title, page_signals
"""

import logging
import re
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

log = logging.getLogger("page_classifier")

TIMEOUT     = 8       # seconds per fetch
MAX_WORKERS = 15      # concurrent fetches
BODY_LIMIT  = 8192    # bytes to read from each page (8 KB is enough for classification)

# ── Page Type Registry ────────────────────────────────────────────────────────
# Maps page_type → (human label, default severity when page-type drives the finding)

PAGE_TYPE_META = {
    "login":        ("Login Page",                 "HIGH"),
    "admin_panel":  ("Admin Panel",                "HIGH"),
    "database_ui":  ("Database Management UI",     "HIGH"),
    "file_listing": ("File / Directory Listing",   "HIGH"),
    "ci_cd":        ("CI/CD Interface",            "HIGH"),
    "api_json":     ("JSON API Endpoint",          "MEDIUM"),
    "api_docs":     ("API Documentation",          "MEDIUM"),
    "monitoring":   ("Monitoring Interface",       "MEDIUM"),
    "dashboard":    ("Internal Dashboard",         "MEDIUM"),
    "staging":      ("Staging / Test Environment", "MEDIUM"),
    "docs":         ("Documentation Site",         "LOW"),
    "error_page":   ("Error Page",                 "LOW"),
    "web_app":      ("Web Application",            "LOW"),
    "static_site":  ("Static Site",                "LOW"),
    "unknown":      ("Unknown",                    "LOW"),
}


# ── Fetch ─────────────────────────────────────────────────────────────────────

def _fetch_page(host: str) -> dict:
    """
    GET the page for a host, trying HTTPS then HTTP.
    Returns a metadata dict consumed by _score_page().
    Returns an empty dict if both schemes fail.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = Request(
            url,
            headers={
                "User-Agent": "shadow-it-classifier/1.0",
                "Accept":     "text/html,application/json,*/*;q=0.9",
            },
        )
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                headers      = resp.headers
                content_type = headers.get("Content-Type", "").lower()
                server       = headers.get("Server", "").lower()
                x_powered_by = headers.get("X-Powered-By", "").lower()
                www_auth     = headers.get("WWW-Authenticate", "").lower()

                body_bytes = resp.read(BODY_LIMIT)
                body = body_bytes.decode("utf-8", errors="replace")

                return {
                    "url":          url,
                    "content_type": content_type,
                    "server":       server,
                    "x_powered_by": x_powered_by,
                    "www_auth":     www_auth,
                    "body":         body.lower(),   # lower-cased for keyword matching
                    "body_raw":     body,           # preserved case for title extraction
                }
        except (HTTPError, URLError, socket.timeout, ConnectionRefusedError, OSError):
            continue

    return {}


# ── Score / Classify ──────────────────────────────────────────────────────────

def _extract_title(body_raw: str) -> str:
    """Pull the text content of the first <title> tag."""
    m = re.search(r"<title[^>]*>(.*?)</title>", body_raw, re.IGNORECASE | re.DOTALL)
    if m:
        # strip HTML entities and whitespace
        raw = re.sub(r"<[^>]+>", "", m.group(1))
        return " ".join(raw.split())[:200]
    return ""


def _score_page(meta: dict) -> tuple[str, str, list[str]]:
    """
    Score page metadata and return (page_type, page_title, signals).

    Uses an additive scoring system: each matching signal contributes points
    toward one or more page types. The highest score wins. Where signals are
    highly specific (phpmyadmin, "Index of /") the score is set high enough
    that they win unambiguously.
    """
    if not meta:
        return "unknown", "", ["host unreachable during page fetch"]

    scores:  defaultdict[str, int] = defaultdict(int)
    signals: list[str]             = []

    body  = meta.get("body", "")          # lower-cased
    raw   = meta.get("body_raw", "")
    ct    = meta.get("content_type", "")
    srv   = meta.get("server", "")
    xpb   = meta.get("x_powered_by", "")
    wauth = meta.get("www_auth", "")

    title = _extract_title(raw)
    t     = title.lower()

    # ── Login ──────────────────────────────────────────────────────────────────
    if re.search(r'<input[^>]+type=["\']?password["\']?', body):
        scores["login"] += 9
        signals.append("password input field found in HTML")

    for kw in ("login", "sign in", "signin", "log in", "authenticate"):
        if kw in t:
            scores["login"] += 6
            signals.append(f"page title contains '{kw}'")
            break

    for kw in ("forgot password", "remember me", "reset password"):
        if kw in body:
            scores["login"] += 2

    if wauth:
        scores["login"] += 6
        signals.append(f"WWW-Authenticate header: {wauth[:60]}")

    # ── Admin panel ────────────────────────────────────────────────────────────
    for kw in ("admin panel", "administration", "control panel", "management console",
               "site administration", "backend", "admin dashboard"):
        if kw in t:
            scores["admin_panel"] += 9
            signals.append(f"page title contains '{kw}'")
            break

    for kw in ("admin panel", "administration panel", "control panel"):
        if kw in body[:3000]:
            scores["admin_panel"] += 5

    # ── Database management UIs (highly specific — score high) ────────────────
    for kw, label in [
        ("phpmyadmin",   "phpMyAdmin"),
        ("adminer",      "Adminer"),
        ("webmin",       "Webmin"),
        ("cpanel",       "cPanel"),
        ("plesk",        "Plesk"),
        ("directadmin",  "DirectAdmin"),
        ("pgadmin",      "pgAdmin"),
        ("mongodb compass", "MongoDB Compass"),
        ("redis commander", "Redis Commander"),
        ("elasticsearch", "Elasticsearch UI"),
    ]:
        if kw in body or kw in srv or kw in xpb or kw in t:
            scores["database_ui"] += 18
            signals.append(f"database management UI detected: {label}")
            break

    # ── File / directory listings ──────────────────────────────────────────────
    if re.search(r"index of\s*/", t):
        scores["file_listing"] += 18
        signals.append("page title is 'Index of /' — directory listing")

    if "parent directory" in body and bool(re.search(r'href="[^"]*\.\."', body)):
        scores["file_listing"] += 10
        signals.append("parent directory link pattern found — directory listing")

    # ── CI/CD ──────────────────────────────────────────────────────────────────
    for kw, label in [
        ("jenkins",       "Jenkins"),
        ("gitlab",        "GitLab"),
        ("travis ci",     "Travis CI"),
        ("teamcity",      "TeamCity"),
        ("bamboo",        "Bamboo"),
        ("circleci",      "CircleCI"),
        ("github actions","GitHub Actions"),
        ("argocd",        "ArgoCD"),
        ("concourse",     "Concourse"),
        ("drone",         "Drone CI"),
    ]:
        if kw in t or kw in body[:4000]:
            scores["ci_cd"] += 14
            signals.append(f"CI/CD tool detected: {label}")
            break

    # ── Monitoring ─────────────────────────────────────────────────────────────
    for kw, label in [
        ("grafana",     "Grafana"),
        ("kibana",      "Kibana"),
        ("prometheus",  "Prometheus"),
        ("zabbix",      "Zabbix"),
        ("datadog",     "Datadog"),
        ("nagios",      "Nagios"),
        ("netdata",     "Netdata"),
        ("graylog",     "Graylog"),
        ("splunk",      "Splunk"),
        ("alertmanager","Alertmanager"),
    ]:
        if kw in t or kw in body[:4000]:
            scores["monitoring"] += 12
            signals.append(f"monitoring tool detected: {label}")
            break

    # ── JSON API ───────────────────────────────────────────────────────────────
    if "application/json" in ct:
        scores["api_json"] += 12
        signals.append("Content-Type: application/json")

    stripped = body.strip()
    if stripped.startswith('{"') or stripped.startswith('[{') or stripped.startswith('[ {'):
        scores["api_json"] += 8
        signals.append("response body is JSON")

    # ── API documentation ──────────────────────────────────────────────────────
    for kw, label in [
        ("swagger",             "Swagger UI"),
        ("openapi",             "OpenAPI"),
        ("graphql playground",  "GraphQL Playground"),
        ("graphiql",            "GraphiQL"),
        ("rapidoc",             "RapiDoc"),
        ("redoc",               "ReDoc"),
        ("api explorer",        "API Explorer"),
    ]:
        if kw in t or kw in body[:4000]:
            scores["api_docs"] += 14
            signals.append(f"API documentation tool detected: {label}")
            break

    # ── Generic dashboard (weaker signal — catches catch-alls) ────────────────
    for kw in ("dashboard", "metrics overview", "system overview", "analytics"):
        if kw in t:
            scores["dashboard"] += 5
            signals.append(f"page title contains '{kw}'")
            break

    # ── Documentation sites ────────────────────────────────────────────────────
    for kw, label in [
        ("readthedocs",  "Read the Docs"),
        ("gitbook",      "GitBook"),
        ("mkdocs",       "MkDocs"),
        ("docusaurus",   "Docusaurus"),
        ("sphinx",       "Sphinx"),
        ("confluence",   "Confluence"),
    ]:
        if kw in body:
            scores["docs"] += 12
            signals.append(f"documentation platform detected: {label}")
            break

    for kw in ("documentation", "docs", "wiki", "readme", "getting started", "user guide"):
        if kw in t:
            scores["docs"] += 5
            signals.append(f"page title suggests documentation: '{kw}'")
            break

    # ── Staging / test environment ─────────────────────────────────────────────
    for kw in ("staging environment", "test environment", "development environment",
               "this is a staging", "do not use in production"):
        if kw in body[:2000]:
            scores["staging"] += 8
            signals.append(f"staging environment label found: '{kw}'")
            break

    # ── Error pages ────────────────────────────────────────────────────────────
    for kw in ("404 not found", "500 internal server error",
               "503 service unavailable", "403 forbidden",
               "page not found", "whitelabel error page"):
        if kw in t:
            scores["error_page"] += 12
            signals.append(f"error page: '{kw}'")
            break

    # ── Generic web app / static site (catch-all, low scores) ─────────────────
    has_forms = "<form" in body
    has_nav   = bool(re.search(r'<nav|navbar|<ul[^>]+menu', body))
    if has_forms or has_nav:
        scores["web_app"] += 2
    else:
        scores["static_site"] += 2

    # ── Pick winner ────────────────────────────────────────────────────────────
    if not any(v > 0 for v in scores.values()):
        return "unknown", title, ["no distinguishing signals found"]

    best_type = max(scores, key=lambda k: scores[k])

    # Deduplicate and trim signals for readability
    seen   = set()
    unique = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    return best_type, title, unique[:6]


# ── Per-host classifier ───────────────────────────────────────────────────────

def _classify_single(item: dict) -> dict:
    """
    Classify one host. Enriches the item dict in-place and returns it.
    Items with status 0 (unreachable) are skipped — page_type = "unknown".
    """
    host   = item.get("host", "")
    status = item.get("status", 0)

    # Skip unreachable hosts
    if status == 0:
        return {**item, "page_type": "unknown", "page_title": "", "page_signals": ["host unreachable"]}

    meta = _fetch_page(host)
    page_type, page_title, page_signals = _score_page(meta)

    log.debug(f"[{host}] page_type={page_type!r}  title={page_title!r}")
    return {
        **item,
        "page_type":    page_type,
        "page_title":   page_title,
        "page_signals": page_signals,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def classify_pages(
    probed_hosts: list[dict],
    max_workers:  int = MAX_WORKERS,
) -> list[dict]:
    """
    Fetch and classify every live host from the status-prober output.

    Args:
        probed_hosts: List of {"host": str, "status": int} dicts.
        max_workers:  Thread-pool size (default 15).

    Returns:
        Same list, with each item enriched with:
          page_type    (str)  — e.g. "login", "admin_panel", "api_json"
          page_title   (str)  — text content of the HTML <title> tag
          page_signals (list) — human-readable signals that drove the classification
    """
    if not probed_hosts:
        return []

    live = [h for h in probed_hosts if h.get("status", 0) != 0]
    dead = [h for h in probed_hosts if h.get("status", 0) == 0]

    log.info(f"Classifying {len(live)} live host(s) ({len(dead)} unreachable skipped)...")

    results_map: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_classify_single, h): h["host"] for h in live}
        done = 0
        for future in as_completed(futures):
            enriched = future.result()
            results_map[enriched["host"]] = enriched
            done += 1
            if done % 5 == 0 or done == len(live):
                log.info(f"  Classified {done}/{len(live)} hosts...")

    # Merge back: preserve original order, add unknowns for dead hosts
    enriched_dead = [
        {**h, "page_type": "unknown", "page_title": "", "page_signals": ["host unreachable"]}
        for h in dead
    ]

    # Reconstruct in original order
    all_enriched = []
    dead_index = {h["host"]: e for h, e in zip(dead, enriched_dead)}
    for original in probed_hosts:
        host = original["host"]
        if host in results_map:
            all_enriched.append(results_map[host])
        else:
            all_enriched.append(dead_index.get(host, {**original, "page_type": "unknown", "page_title": "", "page_signals": []}))

    # Summary log
    type_counts: defaultdict[str, int] = defaultdict(int)
    for item in all_enriched:
        type_counts[item.get("page_type", "unknown")] += 1

    notable = {k: v for k, v in type_counts.items() if k not in ("unknown", "static_site", "web_app")}
    if notable:
        summary = ", ".join(f"{v}× {k}" for k, v in sorted(notable.items(), key=lambda x: -x[1]))
        log.info(f"Classification summary: {summary}")

    return all_enriched
