"""Tests for the ThreatIntFlux collector parsers and feed validator.

No test touches the network: HTTP responses are fixtures, so these run offline and in CI.
Run:  python3 -m pytest tests/ -q
"""
import json
import os
import sys
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import threatintflux_collector as tc  # noqa: E402
import threatintflux_validate as tv  # noqa: E402


class FakeResp:
    def __init__(self, payload=None, text=""):
        self._payload = payload
        self.text = text
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


# ------------------------------------------------------------------ timestamps
@pytest.mark.parametrize("raw,expected", [
    ("2026-11-11T06:00:00+00:00", "2026-11-11T06:00:00+00:00"),
    ("2026-11-11 06:00:00", "2026-11-11T06:00:00+00:00"),
    ("2026-11-11 06:00:00 UTC", "2026-11-11T06:00:00+00:00"),
    ("2026-11-11T06:00:00.123456", "2026-11-11T06:00:00+00:00"),
    ("2026-11-10", "2026-11-10T00:00:00+00:00"),
])
def test_norm_ts_accepts_feed_formats(raw, expected):
    assert tc.norm_ts(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "not a date", "2026-13-45 99:99:99"])
def test_norm_ts_rejects_garbage(raw):
    assert tc.norm_ts(raw) is None


# ------------------------------------------------------------------ collectors (fixtures)
def test_cisa_kev_maps_ransomware_to_critical_and_filters_window():
    recent = {"cveID": "CVE-2026-0001", "vulnerabilityName": "Test RCE", "vendorProject": "V", "product": "P",
              "dateAdded": tc.datetime.now(tc.timezone.utc).strftime("%Y-%m-%d"),
              "knownRansomwareCampaignUse": "Known", "shortDescription": "d", "requiredAction": "patch"}
    old = dict(recent, cveID="CVE-2019-0002", dateAdded="2019-01-01")
    with mock.patch.object(tc.requests, "get", return_value=FakeResp({"vulnerabilities": [recent, old]})):
        out = tc.collect_cisa_kev(days=7)
    assert [i["id"] for i in out] == ["CISA-CVE-2026-0001"]
    assert out[0]["severity"] == "critical" and out[0]["tier"] == "verified"
    assert out[0]["synthetic"] is False


def test_urlhaus_column_mapping():
    csv_text = ("# comment line\n"
                '"1001","2026-11-11 06:00:00","http://bad.example/x.exe","online","2026-11-11 06:00:00",'
                '"malware_download","exe,elf","https://urlhaus.abuse.ch/url/1001/","rep"\n')
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(text=csv_text)):
        out = tc.collect_urlhaus(days=7)
    assert len(out) == 1
    it = out[0]
    assert it["ioc"] == "http://bad.example/x.exe"
    assert it["title"] == "Malware distribution URL (malware_download)"
    assert "exe,elf" in it["summary"] and "online" in it["summary"]
    assert it["date"] == "2026-11-11T06:00:00+00:00"


def test_threatfox_requires_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_KEY", raising=False)
    with pytest.raises(RuntimeError):
        tc.collect_threatfox(days=7)


def test_threatfox_parses_timestamp_and_confidence(monkeypatch):
    monkeypatch.setenv("THREATFOX_KEY", "k")
    payload = {"data": [{"id": 5, "ioc": "203.0.113.9:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
                         "malware_printable": "ExampleBot", "confidence_level": 90,
                         "first_seen_utc": "2026-11-11 06:00:00 UTC", "tags": ["x"]}]}
    with mock.patch.object(tc.requests, "post", return_value=FakeResp(payload)):
        out = tc.collect_threatfox(days=7)
    assert out[0]["severity"] == "high"
    assert out[0]["date"] == "2026-11-11T06:00:00+00:00"


def test_otx_requires_key_and_handles_naive_timestamps(monkeypatch):
    monkeypatch.delenv("OTX_KEY", raising=False)
    with pytest.raises(RuntimeError):
        tc.collect_otx(days=7)
    monkeypatch.setenv("OTX_KEY", "k")
    payload = {"results": [{"id": "p1", "name": "Pulse", "modified": "2026-11-11T06:00:00.000000",
                            "description": "d", "indicators": [{"id": 1, "type": "IPv4",
                            "indicator": "198.51.100.7", "created": "2026-11-10T01:02:03"}]}]}
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(payload)):
        out = tc.collect_otx(days=7)
    assert len(out) == 2
    assert out[0]["date"] == "2026-11-11T06:00:00+00:00"
    assert out[1]["ioc"] == "198.51.100.7"


def test_no_fabrication_when_source_fails(monkeypatch):
    """A failing source must produce zero items, never placeholder data."""
    def boom(*a, **k):
        raise tc.requests.ConnectionError("offline")
    monkeypatch.setattr(tc.requests, "get", boom)
    with pytest.raises(tc.requests.ConnectionError):
        tc.collect_cisa_kev(days=7)


# ------------------------------------------------------------------ validator
def _good_item(**over):
    base = {"id": "X-1", "title": "t", "type": "vuln", "severity": "high", "tier": "verified",
            "source": "NVD", "date": "2026-11-10T00:00:00+00:00", "ioc": "CVE-2026-0001", "mitre": ["T1190"],
            "synthetic": False}
    base.update(over)
    return base


def _feed(items, **over):
    f = {"generated_at": "2026-11-11T00:00:00+00:00", "mode": "live", "sources": [], "items": items}
    f.update(over)
    return f


def test_valid_feed_passes():
    errors, _ = tv.validate(_feed([_good_item()]))
    assert errors == []


@pytest.mark.parametrize("override,needle", [
    ({"severity": "extreme"}, "unknown severity"),
    ({"tier": "trusted-ish"}, "unknown tier"),
    ({"type": "gossip"}, "unknown type"),
    ({"date": "2026-11-10T00:00:00"}, "not ISO-8601 with a timezone"),
    ({"date": "2099-01-01T00:00:00+00:00"}, "in the future"),
    ({"mitre": ["T12"]}, "malformed MITRE"),
    ({"ioc": "not an ioc at all " * 20}, "IOC looks malformed"),
])
def test_invalid_items_are_rejected(override, needle):
    errors, _ = tv.validate(_feed([_good_item(**override)]))
    assert any(needle in e for e in errors), errors


def test_missing_required_and_duplicate_ids():
    bad = _good_item()
    del bad["title"]
    errors, _ = tv.validate(_feed([bad, _good_item(), _good_item()]))
    assert any("missing 'title'" in e for e in errors)
    assert any("duplicate id" in e for e in errors)


def test_live_feed_rejects_synthetic_items():
    errors, _ = tv.validate(_feed([_good_item(synthetic=True)]))
    assert any("marked live but contains" in e for e in errors)


def test_sample_feed_may_contain_synthetic_items():
    errors, warnings = tv.validate(_feed([_good_item(synthetic=True)], mode="sample"))
    assert errors == []
    assert any("synthetic" in w for w in warnings)


def test_source_status_consistency():
    feed = _feed([_good_item(source="NVD")], sources=[
        {"name": "NVD", "status": "ok", "count": 1},            # consistent: an item carries the name
        {"name": "CISA", "status": "ok", "count": 4},           # ok but no item carries "CISA"
        {"name": "URLhaus", "status": "error", "count": 2},     # error yet reports items
        {"name": "X", "status": "maybe", "count": 0},           # unknown status
    ])
    errors, _ = tv.validate(feed)
    assert not any("'NVD'" in e for e in errors)
    assert any("'CISA' is ok and reports 4 items" in e for e in errors)
    assert any("'URLhaus' is in error" in e for e in errors)
    assert any("'X': status must be" in e for e in errors)


def test_top_level_shape():
    errors, _ = tv.validate([])
    assert errors == ["top level must be an object"]
    errors, _ = tv.validate({"generated_at": "nope", "items": "x"})
    assert any("generated_at" in e for e in errors)
    assert any("'items' must be a list" in e for e in errors)


def test_validator_cli_roundtrip(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(_feed([_good_item()])), encoding="utf-8")
    with mock.patch.object(sys, "argv", ["x", str(p)]):
        assert tv.main() == 0
    p.write_text(json.dumps(_feed([_good_item(severity="bogus")])), encoding="utf-8")
    with mock.patch.object(sys, "argv", ["x", str(p)]):
        assert tv.main() == 1
