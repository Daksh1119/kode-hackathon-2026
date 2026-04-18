"""
Status Prober
=============
Bridges subdomain.py → intelligence_engine.py

Takes a list of hostnames (strings) and returns a list of
  {"host": str, "status": int}
by sending a lightweight HTTP HEAD request to each host.

- Tries HTTPS first, falls back to HTTP
- Runs all probes in parallel using ThreadPoolExecutor
- Never raises: failed hosts get status 0 (skipped by the engine)

FIX: removed unreachable `return {"host": host, "status": -1}` statement
     that appeared after an unconditional `return` (dead code).
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

log = logging.getLogger("status_prober")

TIMEOUT        = 6
MAX_WORKERS    = 20
REDIRECT_LIMIT = 3


def _probe_single(host: str) -> dict:
    """
    Probe one host.  Returns {"host": host, "status": int}.
    Status 0  = completely unreachable (DNS failure, connection refused, timeout).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "shadow-it-scanner/1.0",
                "Accept":     "*/*",
            },
        )
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                log.debug(f"[{host}] {scheme.upper()} {resp.status}")
                return {"host": host, "status": resp.status}

        except HTTPError as e:
            # HTTPError is raised for 4xx/5xx — still a valid status code
            log.debug(f"[{host}] {scheme.upper()} HTTP {e.code}")
            return {"host": host, "status": e.code}

        except (URLError, socket.timeout, ConnectionRefusedError, OSError):
            # HTTPS failed — fall through and try HTTP before giving up
            continue

    # Both schemes failed — host is unreachable
    log.debug(f"[{host}] Unreachable")
    return {"host": host, "status": 0}
    # FIX: removed dead `return {"host": host, "status": -1}` that was here


def probe_statuses(
    hostnames:   list[str],
    max_workers: int = MAX_WORKERS,
) -> list[dict]:
    """
    Probe all hostnames in parallel.

    Args:
        hostnames:   List of hostnames e.g. ["admin.acme.com", "dev.acme.com"]
        max_workers: Thread-pool size (default 20)

    Returns:
        List of {"host": str, "status": int}, in the order results arrive.
        Hosts with status 0 are included — the engine skips them naturally.
    """
    if not hostnames:
        return []

    log.info(f"Probing {len(hostnames)} host(s) with {max_workers} workers...")
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_single, h): h for h in hostnames}
        done = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done += 1
            if done % 10 == 0 or done == len(hostnames):
                log.info(f"  Probed {done}/{len(hostnames)} hosts...")

    log.info(f"Probing complete. {len(results)} results.")
    return results