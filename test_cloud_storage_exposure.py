import pytest
from cloud_storage_exposure import (
    extract_base_name,
    generate_storage_name_guesses,
    check_public_cloud_storage,
    check_bucket_listing,
    check_sensitive_files,
    check_write_access,
    check_open_directories,
    _normalize_domain,
)

import sys
import types

# --- Base name extraction tests ---
def test_extract_base_name_simple():
    assert extract_base_name("example.com") == "example"
    assert extract_base_name("www.example.com") == "example"
    assert extract_base_name("https://www.example.com/path") == "example"
    assert extract_base_name("SOMAIYA.co.in") == "somaiya"
    assert extract_base_name("foo.bar.co.uk") == "bar"
    assert extract_base_name("foo.com.au") == "foo"
    assert extract_base_name("foo") == "foo"

# --- Guess generation tests ---
def test_generate_storage_name_guesses():
    guesses = generate_storage_name_guesses("example", max_guesses=6)
    assert guesses[0] == "example"
    assert all(g.startswith("example") for g in guesses)
    assert len(guesses) == 6
    # No duplicates
    assert len(set(guesses)) == len(guesses)

# --- Normalize domain tests ---
def test_normalize_domain():
    assert _normalize_domain("example.com") == "example.com"
    assert _normalize_domain("https://www.example.com/path") == "www.example.com"
    assert _normalize_domain("  EXAMPLE.COM  ") == "example.com"

# --- Public exposure logic (mocked HTTP) ---
import builtins
from urllib.request import urlopen

class DummyResp:
    def __init__(self, status, body=b""):
        self.status = status
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=-1):
        return self._body[:n] if n > 0 else self._body

def dummy_urlopen_factory(status_map, body_map=None):
    """Returns a urlopen replacement that returns DummyResp(status) for known URLs."""
    body_map = body_map or {}
    def dummy_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for key, status in status_map.items():
            if key in url:
                if isinstance(status, Exception):
                    raise status
                body = b""
                for bkey, bval in body_map.items():
                    if bkey in url:
                        body = bval if isinstance(bval, bytes) else bval.encode("utf-8")
                        break
                return DummyResp(status, body)
        # Default: 404
        return DummyResp(404)
    return dummy_urlopen

@pytest.mark.parametrize("status,expected", [
    (200, True),
    (403, False),
    (404, False),
    (500, False),
])
def test_check_public_cloud_storage_status(monkeypatch, status, expected):
    # Patch for both 'example' and 'example-assets' guesses
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({"example": status, "example-assets": status}))
    results = check_public_cloud_storage("example.com", max_guesses=2, include_gcp=False)
    if expected:
        assert any(r["status"] == "PUBLIC" for r in results)
    else:
        assert results == []

def test_check_public_cloud_storage_multiple(monkeypatch):
    # S3 returns 200 for both 'example' and 'example-assets', Azure returns 403, GCS returns 404
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory({
            "example.s3.amazonaws.com": 200,
            "example-assets.s3.amazonaws.com": 200,
            "example.blob.core.windows.net": 403,
            "example-assets.blob.core.windows.net": 403,
            "storage.googleapis.com/example": 404,
            "storage.googleapis.com/example-assets": 404,
        })
    )
    results = check_public_cloud_storage("example.com", max_guesses=2, include_gcp=True)
    # Should find two S3 PUBLIC buckets
    s3_public = [r for r in results if r["service"] == "S3" and r["status"] == "PUBLIC"]
    assert len(s3_public) == 2

# --- Error handling ---
def test_check_public_cloud_storage_timeout(monkeypatch):
    import socket
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({"example-assets": socket.timeout()}))
    results = check_public_cloud_storage("example.com", max_guesses=1, include_gcp=False)
    assert results == []

def test_check_public_cloud_storage_dns_error(monkeypatch):
    import urllib.error
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({"example-assets": urllib.error.URLError("DNS fail")}))
    results = check_public_cloud_storage("example.com", max_guesses=1, include_gcp=False)
    assert results == []

# --- Performance: should not hang ---
def test_check_public_cloud_storage_fast(monkeypatch):
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({}))
    import time
    t0 = time.perf_counter()
    results = check_public_cloud_storage("example.com", max_guesses=6, include_gcp=True)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.5  # Should be fast with all 404s
    assert isinstance(results, list)

# ---------------------------------------------------------------------------
# NEW: Bucket directory listing tests
# ---------------------------------------------------------------------------

S3_LISTING_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example</Name>
  <Contents><Key>secret.txt</Key></Contents>
  <Contents><Key>backup.sql</Key></Contents>
</ListBucketResult>"""

AZURE_LISTING_XML = """<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs><Blob><Name>data.csv</Name></Blob></Blobs>
</EnumerationResults>"""


def test_bucket_listing_s3_detected(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory(
            {"example.s3.amazonaws.com": 200},
            {"example.s3.amazonaws.com": S3_LISTING_XML},
        ),
    )
    results = check_bucket_listing("example.com", max_guesses=1, include_gcp=False)
    assert len(results) >= 1
    hit = results[0]
    assert hit["listing_enabled"] is True
    assert "secret.txt" in hit["sample_objects"]
    assert "backup.sql" in hit["sample_objects"]


def test_bucket_listing_azure_detected(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory(
            {"example.blob.core.windows.net": 200},
            {"example.blob.core.windows.net": AZURE_LISTING_XML},
        ),
    )
    results = check_bucket_listing("example.com", max_guesses=1, include_gcp=False)
    azure_hits = [r for r in results if r["service"] == "Azure Blob"]
    assert len(azure_hits) >= 1
    assert "data.csv" in azure_hits[0]["sample_objects"]


def test_bucket_listing_not_listing(monkeypatch):
    """200 but body is a normal webpage, not XML listing."""
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory(
            {"example.s3.amazonaws.com": 200},
            {"example.s3.amazonaws.com": "<html><body>Hello</body></html>"},
        ),
    )
    results = check_bucket_listing("example.com", max_guesses=1, include_gcp=False)
    assert results == []


# ---------------------------------------------------------------------------
# NEW: Sensitive file leak tests
# ---------------------------------------------------------------------------

def test_sensitive_files_found(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory({
            "example.s3.amazonaws.com/.env": 200,
            "example.s3.amazonaws.com/.git/config": 200,
            # Everything else defaults to 404
        }),
    )
    results = check_sensitive_files("example.com", max_guesses=1, include_gcp=False)
    urls = [r["url"] for r in results]
    assert any(".env" in u for u in urls)
    assert any(".git/config" in u for u in urls)
    assert all(r["status"] == "EXPOSED" for r in results)


def test_sensitive_files_none_found(monkeypatch):
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({}))
    results = check_sensitive_files("example.com", max_guesses=1, include_gcp=False)
    assert results == []


# ---------------------------------------------------------------------------
# NEW: Write access tests
# ---------------------------------------------------------------------------

def test_write_access_writable(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory({"example.s3.amazonaws.com": 200}),
    )
    results = check_write_access("example.com", max_guesses=1, include_gcp=False)
    assert len(results) >= 1
    assert results[0]["status"] == "WRITABLE"
    assert results[0]["severity"] == "CRITICAL"


def test_write_access_denied(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory({"example.s3.amazonaws.com": 403}),
    )
    results = check_write_access("example.com", max_guesses=1, include_gcp=False)
    assert results == []


# ---------------------------------------------------------------------------
# NEW: Open directory tests
# ---------------------------------------------------------------------------

APACHE_DIR_LISTING = """<html><head><title>Index of /backup/</title></head>
<body><h1>Index of /backup/</h1>
<pre><a href="../">Parent Directory</a>
<a href="db_dump.sql">db_dump.sql</a>
<a href="config.bak">config.bak</a>
</pre></body></html>"""


def test_open_directories_found(monkeypatch):
    monkeypatch.setattr(
        "cloud_storage_exposure.urlopen",
        dummy_urlopen_factory(
            {"example.com/backup/": 200},
            {"example.com/backup/": APACHE_DIR_LISTING},
        ),
    )
    results = check_open_directories("example.com")
    assert len(results) >= 1
    hit = results[0]
    assert hit["status"] == "OPEN_DIRECTORY"
    assert hit["path"] == "/backup/"
    assert "db_dump.sql" in hit["sample_files"]


def test_open_directories_none(monkeypatch):
    monkeypatch.setattr("cloud_storage_exposure.urlopen", dummy_urlopen_factory({}))
    results = check_open_directories("example.com")
    assert results == []
