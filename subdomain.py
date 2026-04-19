# """
# Multi-Source Subdomain Enumeration
# ====================================
# Sources (in priority order):
#   1. Shodan          - Infrastructure recon, passive DNS  (needs SHODAN_API_KEY)
#   2. SecurityTrails  - Best-in-class subdomain DB         (needs SECURITYTRAILS_API_KEY)
#   3. VirusTotal      - 500 req/day free                   (needs VIRUSTOTAL_API_KEY)

# API keys are read from environment variables.  Set them before running:

#   Windows (PowerShell):
#     $env:SHODAN_API_KEY         = "your_key"
#     $env:SECURITYTRAILS_API_KEY = "your_key"
#     $env:VIRUSTOTAL_API_KEY     = "your_key"

#   Linux / macOS:
#     export SHODAN_API_KEY="your_key"
#     export SECURITYTRAILS_API_KEY="your_key"
#     export VIRUSTOTAL_API_KEY="your_key"

#   Or create a .env file in the same directory as this script:
#     SHODAN_API_KEY=your_key
#     SECURITYTRAILS_API_KEY=your_key
#     VIRUSTOTAL_API_KEY=your_key

# If a key is missing that source is skipped — the other two still run.

# Usage: python subdomain.py <domain>
# """

# import json
# import logging
# import os
# import sys
# import socket
# import time
# from pathlib import Path
# from urllib.request import urlopen, Request
# from urllib.error import URLError, HTTPError
# from concurrent.futures import ThreadPoolExecutor, as_completed

# # ── Logging ───────────────────────────────────────────────────────────────────
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     datefmt="%H:%M:%S",
# )
# log = logging.getLogger("subdomain_enum")

# # ── Config ────────────────────────────────────────────────────────────────────
# TIMEOUT     = 15
# MAX_RETRIES = 3
# RETRY_CODES = {429, 502, 503, 504}   # 429 = rate-limit → back-off and retry

# PRIORITY = ["Shodan", "SecurityTrails", "VirusTotal"]

# # Maps source name → environment variable name for the API key
# _KEY_ENV_MAP = {
#     "Shodan":         "SHODAN_API_KEY",
#     "SecurityTrails": "SECURITYTRAILS_API_KEY",
#     "VirusTotal":     "VIRUSTOTAL_API_KEY",
# }


# # ── .env loader (no external deps) ───────────────────────────────────────────

# def _load_dotenv() -> None:
#     """
#     Load KEY=VALUE pairs from a .env file in the current working directory
#     into os.environ (only for keys not already set by the shell).
#     Ignores blank lines and comment lines starting with #.
#     """
#     env_file = Path(".env")
#     if not env_file.exists():
#         return
#     with open(env_file, encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()
#             if not line or line.startswith("#") or "=" not in line:
#                 continue
#             key, _, val = line.partition("=")
#             key = key.strip()
#             val = val.strip().strip('"').strip("'")
#             if key and key not in os.environ:
#                 os.environ[key] = val


# _load_dotenv()


# def _api_key(source_name: str) -> str:
#     """Return the API key for source_name, or '' if not configured."""
#     return os.environ.get(_KEY_ENV_MAP.get(source_name, ""), "").strip()


# # ── HTTP helper ───────────────────────────────────────────────────────────────

# def http_get(url: str, source: str, headers: dict | None = None) -> str:
#     """
#     GET a URL with retries on transient errors.
#     Returns the decoded response body as a string.
#     Raises RuntimeError after MAX_RETRIES failed attempts.
#     """
#     req_headers = {"User-Agent": "subdomain-enum/1.0"}
#     if headers:
#         req_headers.update(headers)

#     req = Request(url, headers=req_headers)

#     for attempt in range(1, MAX_RETRIES + 1):
#         try:
#             with urlopen(req, timeout=TIMEOUT) as resp:
#                 return resp.read().decode("utf-8")

#         except socket.timeout:
#             err = f"Timed out after {TIMEOUT}s"

#         except HTTPError as e:
#             if e.code in RETRY_CODES:
#                 err = f"HTTP {e.code} {e.reason}"
#                 # Honour Retry-After header when present (common on rate-limited APIs)
#                 retry_after = int(e.headers.get("Retry-After", 0) or 0)
#                 if retry_after:
#                     log.warning(
#                         f"[{source}] Rate-limited. Waiting {retry_after}s "
#                         f"(Retry-After header)..."
#                     )
#                     time.sleep(retry_after)
#                     continue
#             else:
#                 raise RuntimeError(f"[{source}] HTTP {e.code}: {e.reason}")

#         except URLError as e:
#             err = f"Network error: {e.reason}"

#         if attempt < MAX_RETRIES:
#             wait = 2 ** (attempt - 1)
#             log.warning(
#                 f"[{source}] Attempt {attempt}/{MAX_RETRIES} failed ({err}). "
#                 f"Retrying in {wait}s..."
#             )
#             time.sleep(wait)
#         else:
#             raise RuntimeError(
#                 f"[{source}] All {MAX_RETRIES} attempts failed. Last error: {err}"
#             )


# # ── Source 1: Shodan ──────────────────────────────────────────────────────────

# def fetch_shodan(domain: str) -> set[str]:
#     """
#     Shodan DNS domain API — infrastructure recon, strong passive DNS coverage.

#     Endpoint:
#       GET https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}

#     Response shape:
#       {
#         "domain":     "example.com",
#         "subdomains": ["www", "mail", "dev"],   ← bare labels, no root domain
#         "data": [
#           {"subdomain": "www", "type": "A", "value": "1.2.3.4"},
#           ...
#         ]
#       }

#     We combine both "subdomains" list and "data" records, append the root
#     domain to bare labels, and return a set of fully-qualified hostnames.
#     """
#     api_key = _api_key("Shodan")
#     if not api_key:
#         raise RuntimeError(
#             "[Shodan] SHODAN_API_KEY not set — skipping. "
#             "Get a free key at https://account.shodan.io"
#         )

#     url  = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
#     raw  = http_get(url, "Shodan")
#     data = json.loads(raw)

#     found = set()

#     # "subdomains" list: bare labels like ["www", "mail"]
#     for label in data.get("subdomains", []):
#         label = label.strip().lower().rstrip(".")
#         if not label:
#             continue
#         hostname = f"{label}.{domain}" if not label.endswith(f".{domain}") else label
#         if hostname.endswith(f".{domain}") or hostname == domain:
#             found.add(hostname)

#     # "data" array: each record has a "subdomain" field (also bare labels)
#     for record in data.get("data", []):
#         label = record.get("subdomain", "").strip().lower().rstrip(".")
#         if not label:
#             continue
#         hostname = f"{label}.{domain}" if not label.endswith(f".{domain}") else label
#         if hostname.endswith(f".{domain}") or hostname == domain:
#             found.add(hostname)

#     return found


# # ── Source 2: SecurityTrails ──────────────────────────────────────────────────

# def fetch_securitytrails(domain: str) -> set[str]:
#     """
#     SecurityTrails subdomain list — best-in-class coverage, 50 req/month free.

#     Endpoint:
#       GET https://api.securitytrails.com/v1/domain/{domain}/subdomains
#           ?children_only=false&include_inactive=true
#     Header: APIKEY: {SECURITYTRAILS_API_KEY}

#     Response shape:
#       {
#         "subdomains": ["www", "mail", "dev"],   ← bare labels
#         "subdomain_count": 42
#       }

#     We append the root domain to each bare label to form full hostnames.
#     """
#     api_key = _api_key("SecurityTrails")
#     if not api_key:
#         raise RuntimeError(
#             "[SecurityTrails] SECURITYTRAILS_API_KEY not set — skipping. "
#             "Get a free key at https://securitytrails.com/app/account/credentials"
#         )

#     url = (
#         f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
#         f"?children_only=false&include_inactive=true"
#     )
#     raw  = http_get(url, "SecurityTrails", headers={"APIKEY": api_key})
#     data = json.loads(raw)

#     found = set()
#     for label in data.get("subdomains", []):
#         label = label.strip().lower().rstrip(".")
#         if not label:
#             continue
#         hostname = f"{label}.{domain}"
#         found.add(hostname)

#     return found


# # ── Source 3: VirusTotal ──────────────────────────────────────────────────────

# def fetch_virustotal(domain: str) -> set[str]:
#     """
#     VirusTotal domain subdomains — 500 requests/day on the free tier.

#     Endpoint:
#       GET https://www.virustotal.com/api/v3/domains/{domain}/subdomains
#           ?limit=40
#     Header: x-apikey: {VIRUSTOTAL_API_KEY}

#     Response shape:
#       {
#         "data": [{"id": "sub.example.com", "type": "domain"}, ...],
#         "meta": {"cursor": "<next_page_cursor>"}
#       }

#     The "id" field contains the full hostname.
#     Paginates up to MAX_VT_PAGES pages (40 results each) to respect free tier
#     limits without exhausting the daily quota.
#     """
#     api_key = _api_key("VirusTotal")
#     if not api_key:
#         raise RuntimeError(
#             "[VirusTotal] VIRUSTOTAL_API_KEY not set — skipping. "
#             "Get a free key at https://www.virustotal.com/gui/join-us"
#         )

#     MAX_VT_PAGES = 3   # 3 × 40 = 120 results max; safe for 500 req/day quota
#     found        = set()
#     url          = (
#         f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
#     )
#     headers      = {"x-apikey": api_key}

#     for page_num in range(1, MAX_VT_PAGES + 1):
#         raw  = http_get(url, "VirusTotal", headers=headers)
#         data = json.loads(raw)

#         for item in data.get("data", []):
#             hostname = item.get("id", "").strip().lower()
#             if hostname.endswith(f".{domain}") or hostname == domain:
#                 found.add(hostname)

#         # Follow cursor-based pagination
#         cursor = data.get("meta", {}).get("cursor", "")
#         if not cursor or page_num >= MAX_VT_PAGES:
#             break

#         url = (
#             f"https://www.virustotal.com/api/v3/domains/{domain}"
#             f"/subdomains?limit=40&cursor={cursor}"
#         )
#         time.sleep(0.5)   # polite pacing on free tier

#     return found


# # ── Source Registry ───────────────────────────────────────────────────────────

# FETCHERS = {
#     "Shodan":         fetch_shodan,
#     "SecurityTrails": fetch_securitytrails,
#     "VirusTotal":     fetch_virustotal,
# }


# # ── Parallel Aggregator ───────────────────────────────────────────────────────

# def enumerate_subdomains(domain: str) -> dict:
#     """
#     Query all three sources in parallel.

#     Returns a dict with the schema expected by pipeline.py:
#       {
#         "domain":     str,
#         "merged":     list[str],            # sorted, deduplicated
#         "per_source": dict[str, set[str]],  # results per source
#         "errors":     dict[str, str],       # error message per failed source
#       }

#     Sources with missing API keys are recorded in "errors" and contribute
#     an empty set — they never crash the pipeline.
#     """
#     domain = domain.strip().lower()
#     log.info(f"Starting multi-source enumeration for: {domain}")

#     # Upfront key check — warn immediately so users don't wait then get nothing
#     unconfigured = [n for n in PRIORITY if not _api_key(n)]
#     if unconfigured:
#         log.warning(
#             f"No API key configured for: {', '.join(unconfigured)}. "
#             f"Set them as environment variables or in a .env file."
#         )
#         if len(unconfigured) == len(PRIORITY):
#             log.error(
#                 "All sources are missing API keys. "
#                 "Enumeration will return no results. "
#                 "See the module docstring for setup instructions."
#             )

#     per_source: dict[str, set[str]] = {}
#     errors:     dict[str, str]      = {}

#     def run(name: str) -> tuple[str, set[str]]:
#         log.info(f"[{name}] Fetching...")
#         result = FETCHERS[name](domain)
#         log.info(f"[{name}] Found {len(result)} subdomain(s)")
#         return name, result

#     with ThreadPoolExecutor(max_workers=len(FETCHERS)) as pool:
#         futures = {pool.submit(run, name): name for name in PRIORITY}
#         for future in as_completed(futures):
#             name = futures[future]
#             try:
#                 src, results = future.result()
#                 per_source[src] = results
#             except Exception as e:
#                 log.error(str(e))
#                 errors[name]     = str(e)
#                 per_source[name] = set()

#     merged = sorted(set().union(*per_source.values()))

#     return {
#         "domain":     domain,
#         "merged":     merged,
#         "per_source": per_source,
#         "errors":     errors,
#     }


# # ── CLI ───────────────────────────────────────────────────────────────────────

# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python subdomain.py <domain>")
#         print("Example: python subdomain.py example.com")
#         print()
#         print("Required API keys (env vars or .env file):")
#         for name in PRIORITY:
#             env_var = _KEY_ENV_MAP[name]
#             status  = "✔ set" if _api_key(name) else "✗ NOT SET"
#             print(f"  {env_var:<35} {status}")
#         sys.exit(1)

#     target = sys.argv[1]

#     try:
#         report = enumerate_subdomains(target)

#         # Per-source breakdown
#         print("\n── Per-Source Results " + "─" * 38)
#         for name in PRIORITY:
#             subs   = report["per_source"].get(name, set())
#             status = (
#                 f"✗ FAILED — {report['errors'][name]}"
#                 if name in report["errors"]
#                 else f"✔ {len(subs)} found"
#             )
#             print(f"\n  [{name}] {status}")
#             for s in sorted(subs):
#                 print(f"    {s}")

#         # Merged results
#         print("\n── Merged Unique Subdomains " + "─" * 32)
#         merged = report["merged"]
#         if merged:
#             for sub in merged:
#                 print(f"  {sub}")
#             print(f"\nTotal: {len(merged)} unique subdomain(s) across all sources")
#         else:
#             print("  No subdomains found.")

#     except KeyboardInterrupt:
#         print("\nAborted.")
#         sys.exit(0)


# """
# Multi-Source Subdomain Enumeration
# Sources (in priority order):
#   1. AlienVault OTX   - Most reliable, rich structured JSON
#   2. URLScan.io       - Good independent coverage
#   3. HackerTarget     - Simple plain-text fallback

# Usage: python subdomain_enum.py <domain>
# """

# import json
# import logging
# import sys
# import socket
# import time
# from urllib.request import urlopen, Request
# from urllib.error import URLError, HTTPError
# from concurrent.futures import ThreadPoolExecutor, as_completed

# # ── Logging ───────────────────────────────────────────────────────────────────
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     datefmt="%H:%M:%S",
# )
# log = logging.getLogger("subdomain_enum")

# # ── Config ────────────────────────────────────────────────────────────────────
# TIMEOUT     = 15
# MAX_RETRIES = 3
# RETRY_CODES = {502, 503, 504}

# SOURCES = {
#     "AlienVault OTX": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
#     "URLScan.io"    : "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
#     "HackerTarget"  : "https://api.hackertarget.com/hostsearch/?q={domain}",
# }

# PRIORITY = ["AlienVault OTX", "URLScan.io", "HackerTarget"]


# # ── HTTP Helper ───────────────────────────────────────────────────────────────

# def http_get(url: str, source: str) -> str:
#     """Fetch a URL with retries on transient errors. Returns raw response text."""
#     req = Request(url, headers={"User-Agent": "subdomain-enum/1.0"})

#     for attempt in range(1, MAX_RETRIES + 1):
#         try:
#             with urlopen(req, timeout=TIMEOUT) as resp:
#                 return resp.read().decode("utf-8")

#         except socket.timeout:
#             err = f"Timed out after {TIMEOUT}s"
#         except HTTPError as e:
#             if e.code in RETRY_CODES:
#                 err = f"HTTP {e.code} {e.reason}"
#             else:
#                 raise RuntimeError(f"[{source}] HTTP {e.code}: {e.reason}")
#         except URLError as e:
#             err = f"Network error: {e.reason}"

#         if attempt < MAX_RETRIES:
#             wait = 2 ** (attempt - 1)
#             log.warning(f"[{source}] Attempt {attempt}/{MAX_RETRIES} failed ({err}). Retrying in {wait}s...")
#             time.sleep(wait)
#         else:
#             raise RuntimeError(f"[{source}] All {MAX_RETRIES} attempts failed. Last: {err}")


# # ── Per-Source Parsers ────────────────────────────────────────────────────────

# def fetch_alienvault(domain: str) -> set[str]:
#     """
#     AlienVault OTX — JSON response.
#     Extracts 'hostname' from each passive DNS record.
#     """
#     url = SOURCES["AlienVault OTX"].format(domain=domain)
#     raw = http_get(url, "AlienVault OTX")
#     data = json.loads(raw)

#     found = set()
#     for record in data.get("passive_dns", []):
#         hostname = record.get("hostname", "").strip().lower()
#         if hostname.endswith(f".{domain}") or hostname == domain:
#             found.add(hostname)
#     return found


# def fetch_urlscan(domain: str) -> set[str]:
#     """
#     URLScan.io — JSON response.
#     Extracts page domains and subdomains from scan results.
#     """
#     url = SOURCES["URLScan.io"].format(domain=domain)
#     raw = http_get(url, "URLScan.io")
#     data = json.loads(raw)

#     found = set()
#     for result in data.get("results", []):
#         for field in ["page", "task"]:
#             section = result.get(field, {})
#             for key in ["domain", "apexDomain"]:
#                 val = section.get(key, "").strip().lower()
#                 if val.endswith(f".{domain}") or val == domain:
#                     found.add(val)
#     return found


# def fetch_hackertarget(domain: str) -> set[str]:
#     """
#     HackerTarget — plain text response, one 'subdomain,ip' per line.
#     """
#     url = SOURCES["HackerTarget"].format(domain=domain)
#     raw = http_get(url, "HackerTarget")

#     if "error" in raw.lower() or "API count" in raw:
#         raise RuntimeError(f"[HackerTarget] API limit hit: {raw.strip()}")

#     found = set()
#     for line in raw.splitlines():
#         parts = line.split(",")
#         if parts:
#             subdomain = parts[0].strip().lower()
#             if subdomain.endswith(f".{domain}") or subdomain == domain:
#                 found.add(subdomain)
#     return found


# # ── Source Registry ───────────────────────────────────────────────────────────

# FETCHERS = {
#     "AlienVault OTX": fetch_alienvault,
#     "URLScan.io"    : fetch_urlscan,
#     "HackerTarget"  : fetch_hackertarget,
# }


# # ── Parallel Aggregator ───────────────────────────────────────────────────────

# def enumerate_subdomains(domain: str) -> dict:
#     """
#     Query all sources in parallel.
#     Returns a dict with per-source results and merged unique subdomains.
#     """
#     domain = domain.strip().lower()
#     log.info(f"Starting multi-source enumeration for: {domain}")
#     log.info(f"Querying {len(FETCHERS)} sources in parallel...\n")

#     per_source: dict[str, set[str]] = {}
#     errors:     dict[str, str]      = {}

#     def run(name: str) -> tuple[str, set[str]]:
#         log.info(f"[{name}] Fetching...")
#         result = FETCHERS[name](domain)
#         log.info(f"[{name}] Found {len(result)} subdomain(s)")
#         return name, result

#     with ThreadPoolExecutor(max_workers=len(FETCHERS)) as pool:
#         futures = {pool.submit(run, name): name for name in PRIORITY}
#         for future in as_completed(futures):
#             name = futures[future]
#             try:
#                 src, results = future.result()
#                 per_source[src] = results
#             except Exception as e:
#                 log.error(str(e))
#                 errors[name] = str(e)
#                 per_source[name] = set()

#     # Merge all results
#     merged = sorted(set().union(*per_source.values()))

#     return {
#         "domain"    : domain,
#         "merged"    : merged,
#         "per_source": per_source,
#         "errors"    : errors,
#     }


# # ── CLI ───────────────────────────────────────────────────────────────────────

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python subdomain_enum.py <domain>")
#         print("Example: python subdomain_enum.py example.com")
#         sys.exit(1)

#     target = sys.argv[1]

#     try:
#         report = enumerate_subdomains(target)

#         # Per-source breakdown
#         print("\n── Per-Source Results " + "─" * 38)
#         for name in PRIORITY:
#             subs   = report["per_source"].get(name, set())
#             status = f"✗ FAILED — {report['errors'][name]}" if name in report["errors"] else f"✔ {len(subs)} found"
#             print(f"\n  [{name}] {status}")
#             for s in sorted(subs):
#                 print(f"    {s}")

#         # Merged results
#         print("\n── Merged Unique Subdomains " + "─" * 32)
#         merged = report["merged"]
#         if merged:
#             for sub in merged:
#                 print(f"  {sub}")
#             print(f"\nTotal: {len(merged)} unique subdomain(s) across all sources")
#         else:
#             print("  No subdomains found.")

#     except KeyboardInterrupt:
#         print("\nAborted.")
#         sys.exit(0)




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
  1. crt.sh           - Certificate Transparency logs (free, no key required)
  2. URLScan.io       - Good independent coverage
  3. Shodan           - DNS domain lookup (requires SHODAN_API_KEY)

Usage: python subdomain_enum.py <domain>
Set your Shodan key:  export SHODAN_API_KEY=your_key_here
"""

import json
import logging
import os
import sys
import socket
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

load_dotenv()

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

# Shodan API key — read from environment variable (set before running)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "<YOUR_SHODAN_API_KEY_HERE>")

SOURCES = {
    "crt.sh"    : "https://crt.sh/?q=%25.{domain}&output=json",
    "URLScan.io": "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
    "Shodan"    : "https://api.shodan.io/dns/domain/{domain}?key={key}",
}

PRIORITY = ["crt.sh", "URLScan.io", "Shodan"]


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

def fetch_crtsh(domain: str) -> set[str]:
    """
    crt.sh — Certificate Transparency log aggregator.
    Returns a JSON array; each record's 'name_value' field may contain
    multiple newline-separated hostnames (including wildcards, which we skip).
    No API key required.
    """
    url = SOURCES["crt.sh"].format(domain=domain)
    raw = http_get(url, "crt.sh")

    try:
        records = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"[crt.sh] Failed to parse JSON: {e}")

    found = set()
    for record in records:
        for entry in record.get("name_value", "").split("\n"):
            hostname = entry.strip().lower()
            if hostname.startswith("*"):
                continue   # skip wildcards
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


def fetch_shodan(domain: str) -> set[str]:
    """
    Shodan DNS domain lookup — JSON response.
    Endpoint: GET /dns/domain/{domain}?key=API_KEY
    Response shape:
      {
        "domain": "example.com",
        "subdomains": ["www", "mail", "dev"],   ← bare labels, NOT FQDNs
        "data": [{"subdomain": "www", ...}, ...]
      }
    We reconstruct FQDNs by appending the root domain.
    Requires SHODAN_API_KEY to be set in the environment.
    """
    if not SHODAN_API_KEY:
        raise RuntimeError(
            "[Shodan] SHODAN_API_KEY is not set. "
            "Export it with: export SHODAN_API_KEY=your_key_here"
        )

    url = SOURCES["Shodan"].format(domain=domain, key=SHODAN_API_KEY)
    raw = http_get(url, "Shodan")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"[Shodan] Failed to parse JSON: {e}")

    # Shodan returns {"error": "..."} for invalid keys or exhausted credits
    if "error" in data:
        raise RuntimeError(f"[Shodan] API error: {data['error']}")

    found = set()

    # 'subdomains' is a list of bare labels (e.g. ["www", "mail", "api"])
    for label in data.get("subdomains", []):
        label = label.strip().lower()
        if label:
            found.add(f"{label}.{domain}")

    # 'data' gives richer records; some may have a 'subdomain' field too
    for record in data.get("data", []):
        label = record.get("subdomain", "").strip().lower()
        if label:
            found.add(f"{label}.{domain}")

    return found


# ── Source Registry ───────────────────────────────────────────────────────────

FETCHERS = {
    "crt.sh"    : fetch_crtsh,
    "URLScan.io": fetch_urlscan,
    "Shodan"    : fetch_shodan,
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