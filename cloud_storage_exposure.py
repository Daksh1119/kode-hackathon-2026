"""
Cloud Storage & Web Exposure Scanner.

Checks for:
  1. Publicly accessible cloud storage buckets (S3, Azure Blob, GCS)
  2. Bucket directory listing (object enumeration)
  3. Sensitive file leaks inside buckets
  4. Write-access misconfiguration on buckets
  5. Open directories on the target web server

This module is intentionally standalone so it can be dropped into hackathon
pipelines without changing existing code.
"""

from __future__ import annotations

import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def extract_base_name(root_domain: str) -> str:
    """
    Extract a base name from a root domain.

    Examples:
      "example.com" -> "example"
      "https://www.example.com/path" -> "example"
      "somaiya.co.in" -> "somaiya"
    """
    if not root_domain or not root_domain.strip():
        raise ValueError("root_domain must be a non-empty string")

    value = root_domain.strip().lower()
    if "://" not in value:
        value = f"https://{value}"

    host = urlparse(value).netloc or urlparse(value).path
    host = host.split("@")[ -1].split(":")[0].strip(".")

    if not host:
        raise ValueError("Could not parse a host from root_domain")

    labels = [p for p in host.split(".") if p]
    if not labels:
        raise ValueError("Could not parse domain labels")

    # Handle common multi-part TLDs in a lightweight way.
    common_second_level_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "co.in", "org.in", "net.in",
        "com.au", "net.au", "org.au",
    }

    if len(labels) >= 3 and ".".join(labels[-2:]) in common_second_level_tlds:
        base = labels[-3]
    elif len(labels) >= 2:
        base = labels[-2]
    else:
        base = labels[0]

    cleaned = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in base).strip("-")
    if not cleaned:
        raise ValueError("Derived base name is empty")

    return cleaned


def _normalize_domain(root_domain: str) -> str:
    """Return a clean 'host.tld' string from user input."""
    value = root_domain.strip().lower()
    if "://" not in value:
        value = f"https://{value}"
    host = urlparse(value).netloc or urlparse(value).path
    return host.split("@")[-1].split(":")[0].strip(".")


def generate_storage_name_guesses(base_name: str, max_guesses: int = 6) -> list[str]:
    """
    Generate a small set of likely storage resource names.

    Keeps guesses intentionally small for hackathon safety and speed.
    """
    if max_guesses < 1:
        return []

    suffixes = ["assets", "backup", "dev", "media", "files", "static", "docs"]
    guesses = [f"{base_name}-{suffix}" for suffix in suffixes]

    # Add the plain base name as a common bucket pattern.
    guesses.insert(0, base_name)

    deduped: list[str] = []
    seen = set()
    for item in guesses:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped[:max_guesses]


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

_UA = "shadow-it-cloud-check/1.0"


def _http_get_status(url: str, timeout: float) -> int | None:
    req = Request(
        url,
        method="GET",
        headers={"User-Agent": _UA, "Accept": "*/*"},
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 0) or 0)
    except HTTPError as err:
        return int(err.code)
    except (URLError, socket.timeout, TimeoutError, OSError):
        return None


def _http_get_full(url: str, timeout: float) -> tuple[int | None, str]:
    """GET request returning (status_code, body_snippet)."""
    req = Request(url, method="GET", headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            body = resp.read(8192).decode("utf-8", errors="replace")
            return status, body
    except HTTPError as err:
        try:
            body = err.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return int(err.code), body
    except (URLError, socket.timeout, TimeoutError, OSError):
        return None, ""


def _http_put_test(url: str, timeout: float) -> int | None:
    """Attempt a PUT with a tiny payload to probe write access."""
    payload = b"cloud-exposure-write-test"
    req = Request(
        url,
        method="PUT",
        data=payload,
        headers={
            "User-Agent": _UA,
            "Content-Type": "text/plain",
            "Content-Length": str(len(payload)),
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 0) or 0)
    except HTTPError as err:
        return int(err.code)
    except (URLError, socket.timeout, TimeoutError, OSError):
        return None


# ---------------------------------------------------------------------------
# Provider URL generators
# ---------------------------------------------------------------------------

def _provider_targets(bucket_name: str, include_gcp: bool) -> Iterable[tuple[str, str]]:
    yield "S3", f"http://{bucket_name}.s3.amazonaws.com"
    yield "Azure Blob", f"https://{bucket_name}.blob.core.windows.net"
    if include_gcp:
        yield "GCS", f"https://storage.googleapis.com/{bucket_name}"


# ---------------------------------------------------------------------------
# 1. Public bucket check (original)
# ---------------------------------------------------------------------------

def check_public_cloud_storage(
    root_domain: str,
    *,
    timeout: float = 2.0,
    max_guesses: int = 6,
    include_gcp: bool = True,
    max_workers: int = 12,
) -> list[dict[str, str]]:
    """
    Discover likely publicly accessible cloud storage resources.

    Rules:
    - Generate only a small set of guesses (5-8 recommended).
    - Send GET requests with short timeouts.
    - Mark only HTTP 200 as PUBLIC.
    - Ignore 403/404 and all request exceptions.

    Returns:
      [
        {
          "service": "S3",
          "bucket": "example-assets",
          "url": "http://example-assets.s3.amazonaws.com",
          "status": "PUBLIC",
        }
      ]
    """
    start = time.perf_counter()

    base_name = extract_base_name(root_domain)
    guesses = generate_storage_name_guesses(base_name, max_guesses=max_guesses)

    if not guesses:
        return []

    jobs: list[tuple[str, str, str]] = []
    for bucket in guesses:
        for service, url in _provider_targets(bucket, include_gcp=include_gcp):
            jobs.append((service, bucket, url))

    findings: list[dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        future_map = {
            pool.submit(_http_get_status, url, timeout): (service, bucket, url)
            for service, bucket, url in jobs
        }

        for future in as_completed(future_map):
            service, bucket, url = future_map[future]
            status_code = future.result()
            if status_code == 200:
                findings.append(
                    {
                        "service": service,
                        "bucket": bucket,
                        "url": url,
                        "status": "PUBLIC",
                    }
                )

    # Stable ordering for predictable downstream JSON/reporting.
    findings.sort(key=lambda x: (x["service"], x["bucket"], x["url"]))

    # Keep this function lightweight and bounded. Caller can inspect externally if needed.
    _ = time.perf_counter() - start
    return findings


# ---------------------------------------------------------------------------
# 2. Bucket directory listing (object enumeration)
# ---------------------------------------------------------------------------

_LISTING_MARKERS = {
    "S3":         ["<ListBucketResult", "<Contents>", "<Key>"],
    "GCS":        ["<ListBucketResult", "<Contents>", "<Key>"],
    "Azure Blob": ["<EnumerationResults", "<Blob>", "<Name>"],
}


def _extract_keys_from_xml(body: str, service: str) -> list[str]:
    """Pull object keys / blob names from an XML listing response."""
    if service in ("S3", "GCS"):
        return re.findall(r"<Key>(.+?)</Key>", body)
    elif service == "Azure Blob":
        return re.findall(r"<Name>(.+?)</Name>", body)
    return []


def check_bucket_listing(
    root_domain: str,
    *,
    timeout: float = 3.0,
    max_guesses: int = 6,
    include_gcp: bool = True,
    max_workers: int = 12,
) -> list[dict]:
    """
    Check if cloud storage buckets expose directory listings.

    A bucket with listing enabled lets anyone enumerate all stored objects —
    a severe misconfiguration.
    """
    base_name = extract_base_name(root_domain)
    guesses = generate_storage_name_guesses(base_name, max_guesses=max_guesses)
    if not guesses:
        return []

    jobs: list[tuple[str, str, str]] = []
    for bucket in guesses:
        for service, url in _provider_targets(bucket, include_gcp=include_gcp):
            jobs.append((service, bucket, url))

    findings: list[dict] = []

    def _probe(service: str, bucket: str, url: str) -> dict | None:
        status, body = _http_get_full(url, timeout)
        if status != 200:
            return None
        markers = _LISTING_MARKERS.get(service, [])
        if any(m in body for m in markers):
            keys = _extract_keys_from_xml(body, service)
            return {
                "service": service,
                "bucket": bucket,
                "url": url,
                "listing_enabled": True,
                "sample_objects": keys[:15],
                "total_objects_in_page": len(keys),
            }
        return None

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        futures = {
            pool.submit(_probe, svc, bkt, u): (svc, bkt)
            for svc, bkt, u in jobs
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda x: (x["service"], x["bucket"]))
    return findings


# ---------------------------------------------------------------------------
# 3. Sensitive file / common leak scanner
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, description, severity)
    (".env",                "Environment variables / secrets",       "CRITICAL"),
    (".git/config",         "Git repository configuration",          "HIGH"),
    (".git/HEAD",           "Git HEAD reference",                    "HIGH"),
    ("wp-config.php",       "WordPress database credentials",        "CRITICAL"),
    ("config.json",         "Application configuration",             "MEDIUM"),
    ("config.yaml",         "Application configuration",             "MEDIUM"),
    ("config.yml",          "Application configuration",             "MEDIUM"),
    ("credentials.json",    "Service account credentials",           "CRITICAL"),
    ("backup.sql",          "Database backup dump",                  "CRITICAL"),
    ("dump.sql",            "Database dump",                         "CRITICAL"),
    ("database.yml",        "Database connection config",            "HIGH"),
    (".htpasswd",           "Apache password file",                  "HIGH"),
    (".htaccess",           "Apache access configuration",           "MEDIUM"),
    ("id_rsa",              "SSH private key",                       "CRITICAL"),
    ("id_rsa.pub",          "SSH public key",                        "LOW"),
    (".aws/credentials",    "AWS credentials file",                  "CRITICAL"),
    ("web.config",          "IIS / ASP.NET configuration",           "HIGH"),
    ("appsettings.json",    "ASP.NET app settings",                  "HIGH"),
    (".dockerenv",          "Docker environment marker",             "LOW"),
    ("docker-compose.yml",  "Docker Compose config",                 "MEDIUM"),
    ("Dockerfile",          "Docker build file",                     "LOW"),
    ("package.json",        "Node.js dependencies",                  "LOW"),
    (".npmrc",              "npm auth tokens",                       "HIGH"),
    ("composer.json",       "PHP dependencies",                      "LOW"),
    ("requirements.txt",    "Python dependencies",                   "LOW"),
    ("phpinfo.php",         "PHP info page (info leak)",             "MEDIUM"),
    ("server-status",       "Apache server-status",                  "MEDIUM"),
    ("elmah.axd",           "ASP.NET error log",                     "HIGH"),
    ("debug.log",           "Debug log file",                        "MEDIUM"),
    ("error.log",           "Error log file",                        "MEDIUM"),
    ("access.log",          "Access log file",                       "MEDIUM"),
]


def check_sensitive_files(
    root_domain: str,
    *,
    timeout: float = 3.0,
    max_guesses: int = 6,
    include_gcp: bool = True,
    max_workers: int = 20,
) -> list[dict]:
    """
    Probe cloud buckets for common sensitive / leaked files.

    Only reports paths that return HTTP 200 (i.e. are actually accessible).
    """
    base_name = extract_base_name(root_domain)
    guesses = generate_storage_name_guesses(base_name, max_guesses=max_guesses)
    if not guesses:
        return []

    # Build URL list: bucket_base_url + "/" + sensitive_path
    jobs: list[tuple[str, str, str, str, str]] = []
    for bucket in guesses:
        for service, base_url in _provider_targets(bucket, include_gcp=include_gcp):
            for path, desc, severity in SENSITIVE_PATHS:
                full_url = f"{base_url}/{path}"
                jobs.append((service, bucket, full_url, desc, severity))

    findings: list[dict] = []

    def _probe(service, bucket, url, desc, severity):
        status = _http_get_status(url, timeout)
        if status == 200:
            return {
                "service": service,
                "bucket": bucket,
                "url": url,
                "file": url.split("/", 4)[-1] if "/" in url else url,
                "description": desc,
                "severity": severity,
                "status": "EXPOSED",
            }
        return None

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        futures = {
            pool.submit(_probe, *job): job for job in jobs
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["service"], x["bucket"]))
    return findings


# ---------------------------------------------------------------------------
# 4. Write-access probe
# ---------------------------------------------------------------------------

def check_write_access(
    root_domain: str,
    *,
    timeout: float = 3.0,
    max_guesses: int = 6,
    include_gcp: bool = True,
    max_workers: int = 12,
) -> list[dict]:
    """
    Probe whether any discovered bucket allows unauthenticated writes (PUT).

    A writable bucket is a severe vulnerability — attackers can upload
    malware, deface content, or pivot further.
    """
    base_name = extract_base_name(root_domain)
    guesses = generate_storage_name_guesses(base_name, max_guesses=max_guesses)
    if not guesses:
        return []

    jobs: list[tuple[str, str, str]] = []
    for bucket in guesses:
        for service, base_url in _provider_targets(bucket, include_gcp=include_gcp):
            test_url = f"{base_url}/_exposure_write_test_{int(time.time())}.txt"
            jobs.append((service, bucket, test_url))

    findings: list[dict] = []

    def _probe(service, bucket, url):
        status = _http_put_test(url, timeout)
        if status is not None and status in (200, 201, 204):
            return {
                "service": service,
                "bucket": bucket,
                "url": url,
                "status": "WRITABLE",
                "severity": "CRITICAL",
            }
        return None

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        futures = {pool.submit(_probe, *job): job for job in jobs}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda x: (x["service"], x["bucket"]))
    return findings


# ---------------------------------------------------------------------------
# 5. Open directory scanner on target web server
# ---------------------------------------------------------------------------

OPEN_DIR_PATHS: list[str] = [
    "/",
    "/backup/",
    "/backups/",
    "/admin/",
    "/uploads/",
    "/upload/",
    "/files/",
    "/data/",
    "/tmp/",
    "/temp/",
    "/logs/",
    "/log/",
    "/debug/",
    "/config/",
    "/private/",
    "/secret/",
    "/dump/",
    "/db/",
    "/database/",
    "/api/",
    "/old/",
    "/archive/",
    "/test/",
    "/staging/",
    "/dev/",
    "/wp-content/uploads/",
    "/public/",
    "/assets/",
    "/static/",
    "/media/",
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/.well-known/",
]

_DIR_LISTING_SIGNATURES = [
    "Index of /",
    "Directory listing for",
    "<title>Index of",
    "Parent Directory",
    "[To Parent Directory]",
    "Directory Listing",
    "<pre><a href=",
]


def check_open_directories(
    root_domain: str,
    *,
    timeout: float = 1.0,
    max_workers: int = 150,
) -> list[dict]:
    """
    Scan the target web server for open / exposed directories.

    Looks for classic directory-listing signatures in the HTTP response
    body (Apache, Nginx, IIS, Python http.server, etc.).
    """
    host = _normalize_domain(root_domain)
    if not host:
        return []

    base_urls = [f"https://{host}", f"http://{host}"]
    findings: list[dict] = []

    def _probe(base_url: str, path: str) -> dict | None:
        url = f"{base_url}{path}"
        status, body = _http_get_full(url, timeout)
        if status == 200 and body:
            body_lower = body.lower()
            for sig in _DIR_LISTING_SIGNATURES:
                if sig.lower() in body_lower:
                    # Try to extract listed files
                    listed = re.findall(r'href="([^"]+)"', body)
                    listed = [
                        f for f in listed
                        if f not in ("../", "/", "#", "?C=N;O=D", "?C=M;O=A",
                                     "?C=S;O=A", "?C=D;O=A", "?C=N;O=A",
                                     "?C=M;O=D", "?C=S;O=D", "?C=D;O=D")
                        and not f.startswith("?")
                    ]
                    return {
                        "url": url,
                        "path": path,
                        "status": "OPEN_DIRECTORY",
                        "severity": "HIGH" if any(
                            k in path for k in
                            ("/backup", "/db", "/dump", "/private",
                             "/secret", "/.git", "/.svn", "/config",
                             "/log")
                        ) else "MEDIUM",
                        "sample_files": listed[:15],
                        "signature_matched": sig,
                    }
        return None

    jobs = [(base, path) for base in base_urls for path in OPEN_DIR_PATHS]

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(jobs)))) as pool:
        futures = {pool.submit(_probe, b, p): (b, p) for b, p in jobs}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                # Deduplicate by path (https and http may both hit)
                if not any(f["path"] == result["path"] for f in findings):
                    findings.append(result)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["path"]))
    return findings


# ---------------------------------------------------------------------------
# 6. Full scan orchestrator
# ---------------------------------------------------------------------------

def full_scan(
    root_domain: str,
    *,
    timeout: float = 3.0,
    max_guesses: int = 6,
    include_gcp: bool = True,
) -> dict[str, list]:
    """
    Run all exposure checks and return a consolidated report.
    """
    return {
        "public_buckets": check_public_cloud_storage(
            root_domain, timeout=timeout, max_guesses=max_guesses,
            include_gcp=include_gcp,
        ),
        "bucket_listings": check_bucket_listing(
            root_domain, timeout=timeout, max_guesses=max_guesses,
            include_gcp=include_gcp,
        ),
        "sensitive_files": check_sensitive_files(
            root_domain, timeout=timeout, max_guesses=max_guesses,
            include_gcp=include_gcp,
        ),
        "write_access": check_write_access(
            root_domain, timeout=timeout, max_guesses=max_guesses,
            include_gcp=include_gcp,
        ),
        "open_directories": check_open_directories(
            root_domain, timeout=timeout,
        ),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[33m",  # dark yellow
    "LOW":      "\033[36m",  # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[92m"
_RED = "\033[91m"


def _sev(label: str) -> str:
    color = _SEV_COLORS.get(label, "")
    return f"{color}{label}{_RESET}"


def _print_banner(domain: str) -> None:
    print(f"\n{_BOLD}{'='*65}")
    print(f"   CLOUD STORAGE & WEB EXPOSURE SCANNER")
    print(f"   Target : {domain}")
    print(f"   Time   : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}{_RESET}\n")


def _print_section(title: str, items: list, empty_msg: str) -> None:
    print(f"\n{_BOLD}--- {title} ---{_RESET}")
    if not items:
        print(f"  {_GREEN}[OK]{_RESET} {empty_msg}")
        return
    count = len(items)
    print(f"  {_RED}[!]{_RESET} Found {_BOLD}{count}{_RESET} issue(s):\n")
    for i, item in enumerate(items, 1):
        sev = item.get("severity", item.get("status", ""))
        print(f"  {_BOLD}{i}.{_RESET} [{_sev(sev)}]")
        for key, val in item.items():
            if key == "severity":
                continue
            if key == "sample_objects" or key == "sample_files":
                if val:
                    print(f"       {key}:")
                    for obj in val[:10]:
                        print(f"         - {obj}")
                    if len(val) > 10:
                        print(f"         ... and {len(val)-10} more")
                continue
            print(f"       {key:20s}: {val}")
        print()


def main() -> None:
    import sys

    # Accept domain from CLI argument or prompt interactively
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    else:
        domain = input("Enter target domain (e.g. somaiya.edu): ").strip()

    if not domain:
        print("Error: No domain provided.")
        sys.exit(1)

    _print_banner(domain)

    print(f"{_DIM}Running all checks concurrently...{_RESET}\n")
    start = time.perf_counter()

    # Run all scans concurrently via thread pool
    scan_fns = {
        "public_buckets": lambda: check_public_cloud_storage(
            domain, timeout=1.0, max_guesses=6, include_gcp=True
        ),
        "bucket_listings": lambda: check_bucket_listing(
            domain, timeout=1.0, max_guesses=6, include_gcp=True
        ),
        "sensitive_files": lambda: check_sensitive_files(
            domain, timeout=1.0, max_guesses=6, include_gcp=True
        ),
        "write_access": lambda: check_write_access(
            domain, timeout=1.0, max_guesses=6, include_gcp=True
        ),
        "open_directories": lambda: check_open_directories(
            domain, timeout=1.0
        ),
    }

    results: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        future_map = {pool.submit(fn): name for name, fn in scan_fns.items()}
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:
                print(f"  [WARN] {name} scan failed: {exc}")
                results[name] = []

    elapsed = time.perf_counter() - start

    # Print results by category
    _print_section(
        "PUBLIC BUCKETS (S3 / Azure / GCS)",
        results.get("public_buckets", []),
        "No publicly accessible buckets found.",
    )
    _print_section(
        "BUCKET DIRECTORY LISTING (object enumeration)",
        results.get("bucket_listings", []),
        "No buckets with directory listing enabled.",
    )
    _print_section(
        "SENSITIVE FILE LEAKS (in buckets)",
        results.get("sensitive_files", []),
        "No sensitive files found in buckets.",
    )
    _print_section(
        "WRITE ACCESS (unauthenticated PUT)",
        results.get("write_access", []),
        "No writable buckets detected.",
    )
    _print_section(
        "OPEN DIRECTORIES (on target web server)",
        results.get("open_directories", []),
        "No open directories found on the web server.",
    )

    # Summary
    total_issues = sum(len(v) for v in results.values())
    crit_count = sum(
        1 for v in results.values()
        for item in v if item.get("severity") == "CRITICAL"
    )
    high_count = sum(
        1 for v in results.values()
        for item in v if item.get("severity") == "HIGH"
    )

    print(f"\n{_BOLD}{'='*65}")
    print(f"  SCAN COMPLETE  |  {elapsed:.1f}s  |  {total_issues} issue(s) found")
    if crit_count:
        print(f"  {_RED}CRITICAL: {crit_count}{_RESET}", end="")
    if high_count:
        print(f"  {_SEV_COLORS['HIGH']}HIGH: {high_count}{_RESET}", end="")
    if crit_count or high_count:
        print()
    print(f"{'='*65}{_RESET}\n")

    # Optionally dump JSON report
    if "--json" in sys.argv:
        report_name = f"{extract_base_name(domain)}_exposure_report.json"
        with open(report_name, "w", encoding="utf-8") as fp:
            json.dump(
                {"domain": domain, "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "results": results},
                fp, indent=2,
            )
        print(f"  JSON report saved to: {report_name}\n")


if __name__ == "__main__":
    main()
