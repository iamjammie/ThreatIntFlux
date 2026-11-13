"""Tests for the local companion server. They run real HTTP on 127.0.0.1 with an OS-chosen port.

The collector is replaced by a stub, so no test touches the network.
"""
import http.client
import json
import os
import sys
import threading
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import serve  # noqa: E402


@pytest.fixture
def running():
    server = serve.make_server(0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()
    server.server_close()


def _req(port, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}"}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, r.getheader("Content-Type"), data


def test_serves_console_and_security_headers(running):
    status, ctype, body = _req(running, "GET", "/")
    assert status == 200 and ctype.startswith("text/html")
    assert b"ThreatInt" in body
    conn = http.client.HTTPConnection("127.0.0.1", running, timeout=10)
    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{running}"})
    r = conn.getresponse()
    r.read()
    assert "default-src 'self'" in r.getheader("Content-Security-Policy")
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    conn.close()


@pytest.mark.parametrize("path", ["/.git/config", "/serve.py", "/../etc/passwd", "/tests/test_serve.py",
                                  "/threatintflux_collector.py"])
def test_only_whitelisted_files_are_served(running, path):
    status, _, _ = _req(running, "GET", path)
    assert status == 404


def test_status_reports_key_presence_never_values(running, monkeypatch):
    monkeypatch.setenv("THREATFOX_KEY", "super-secret-value")
    monkeypatch.delenv("OTX_KEY", raising=False)
    status, _, body = _req(running, "GET", "/api/status")
    assert status == 200
    assert b"super-secret-value" not in body
    payload = json.loads(body)
    assert payload["keys"]["THREATFOX_KEY"] is True and payload["keys"]["OTX_KEY"] is False


def test_rejects_foreign_host_header(running):
    status, _, _ = _req(running, "GET", "/api/status", host="evil.example")
    assert status == 421


def test_sync_requires_custom_header(running):
    status, _, _ = _req(running, "POST", "/api/sync", body=b"{}")
    assert status == 403


def test_sync_runs_collector_with_bounded_days(running):
    stub_feed = {"generated_at": "2026-11-12T00:00:00+00:00", "mode": "live", "sources": [],
                 "items": [], "articles": []}
    with mock.patch.object(serve, "run_sync", return_value=stub_feed) as run:
        status, _, body = _req(running, "POST", "/api/sync", body=json.dumps({"days": 999}).encode(),
                               headers={"X-TIF": "1", "Content-Type": "application/json"})
    assert status == 200 and json.loads(body) == stub_feed
    assert run.call_args.args[0] == 30  # clamped to the maximum window


def test_sync_rejects_bad_input(running):
    h = {"X-TIF": "1"}
    assert _req(running, "POST", "/api/sync", body=b"not json", headers=h)[0] == 400
    assert _req(running, "POST", "/api/sync", body=json.dumps({"days": "x"}).encode(), headers=h)[0] == 400
    assert _req(running, "POST", "/api/sync", body=b"x" * 5000, headers=h)[0] == 413
    assert _req(running, "POST", "/api/other", body=b"{}", headers=h)[0] == 404


def test_sync_failure_inside_collector_is_reported_in_feed_not_as_500(running):
    """build_feed records source errors itself, so a sync with every source down still returns a feed."""
    import threatintflux_collector as tc
    with mock.patch.object(tc, "SOURCES", [("Down", lambda d: (_ for _ in ()).throw(RuntimeError("offline")))]), \
         mock.patch.object(tc, "NEWS_FEEDS", []):
        status, _, body = _req(running, "POST", "/api/sync", body=b"{}", headers={"X-TIF": "1"})
    assert status == 200
    feed = json.loads(body)
    assert feed["sources"] == [{"name": "Down", "status": "error", "count": 0, "error": "offline"}]
    assert feed["items"] == [] and feed["articles"] == []
