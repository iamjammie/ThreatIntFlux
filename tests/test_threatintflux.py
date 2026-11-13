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
    def __init__(self, payload=None, text="", content=None):
        self._payload = payload
        self.text = text
        self.content = content if content is not None else text.encode("utf-8")
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


# ------------------------------------------------------------------ batch 1 collectors (fixtures)
def _now_str(hours_ago=1):
    return (tc.datetime.now(tc.timezone.utc) - tc.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_ransomware_claims_are_unverified_and_stable_ids():
    recent = {"post_title": "Example Holdings Ltd", "group_name": "examplegroup",
              "discovered": _now_str(2), "country": "IN"}
    old = {"post_title": "Old Victim", "group_name": "examplegroup", "discovered": "2019-01-01 00:00:00"}
    with mock.patch.object(tc.requests, "get", return_value=FakeResp([recent, old])):
        first = tc.collect_ransomware_live(days=7)
    with mock.patch.object(tc.requests, "get", return_value=FakeResp([recent, old])):
        second = tc.collect_ransomware_live(days=7)
    assert len(first) == 1
    it = first[0]
    assert it["tier"] == "unverified" and it["type"] == "leak"
    assert it["source"] == tc.RANSOM_SOURCE
    assert it["id"] == second[0]["id"], "ids must be stable across runs so the feed de-duplicates"
    assert it["region"] == "IN" and it["actor"] == "examplegroup"
    assert "not confirmed by the victim" in it["summary"]


def test_feodo_marks_online_c2_high_and_offline_medium():
    entries = [
        {"ip_address": "203.0.113.10", "port": 443, "status": "online", "malware": "Dridex",
         "last_online": _now_str(1), "first_seen": "2026-11-01 00:00:00", "country": "US", "as_name": "EXAMPLE-AS"},
        {"ip_address": "203.0.113.11", "port": 8080, "status": "offline", "malware": "QakBot",
         "last_online": _now_str(2), "first_seen": "2026-11-01 00:00:00"},
        {"ip_address": "203.0.113.12", "port": 80, "status": "offline", "malware": "Emotet",
         "last_online": "2019-01-01 00:00:00", "first_seen": "2019-01-01 00:00:00"},
    ]
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(entries)):
        out = tc.collect_feodo(days=7)
    assert [i["ioc"] for i in out] == ["203.0.113.10", "203.0.113.11"]
    assert out[0]["severity"] == "high" and out[1]["severity"] == "medium"
    assert out[0]["tier"] == "trusted" and out[0]["source"] == tc.FEODO_SOURCE
    assert out[0]["title"] == "Dridex botnet C2 203.0.113.10:443"


def test_ghsa_maps_severity_cve_and_packages(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    advisories = [
        {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-1234", "summary": "Path traversal",
         "description": "Details of the flaw.", "severity": "critical", "published_at": _now_str(3),
         "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "example-lib"}},
                             {"package": {"ecosystem": "npm", "name": "example-lib"}}]},
        {"ghsa_id": "GHSA-dddd-eeee-ffff", "cve_id": None, "summary": "Old", "severity": "low",
         "published_at": "2019-01-01T00:00:00Z", "vulnerabilities": []},
    ]
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(advisories)) as get:
        out = tc.collect_ghsa(days=7)
    assert len(out) == 1
    it = out[0]
    assert it["id"] == "GHSA-GHSA-aaaa-bbbb-cccc"
    assert it["severity"] == "critical" and it["tier"] == "verified" and it["type"] == "vuln"
    assert it["ioc"] == "CVE-2026-1234"
    assert it["title"].startswith("CVE-2026-1234: Path traversal")
    assert it["summary"].endswith("Packages: npm/example-lib.")
    assert "Authorization" not in get.call_args.kwargs["headers"]


def test_ghsa_sends_token_when_set(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    with mock.patch.object(tc.requests, "get", return_value=FakeResp([])) as get:
        tc.collect_ghsa(days=7)
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer t0k"


def test_mitre_export_uses_display_tactic_names_and_skips_revoked():
    bundle = {"objects": [
        {"type": "attack-pattern", "name": "Valid Account", "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1078"}],
         "kill_chain_phases": [{"phase_name": "defense-evasion"}, {"phase_name": "initial-access"}]},
        {"type": "attack-pattern", "name": "Old", "revoked": True, "external_references": [
            {"source_name": "mitre-attack", "external_id": "T9999"}], "kill_chain_phases": []},
        {"type": "attack-pattern", "name": "C2 Thing", "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1071"}],
         "kill_chain_phases": [{"phase_name": "command-and-control"}]},
    ]}
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(bundle)):
        techs = tc.collect_mitre_stix()
    assert [t["id"] for t in techs] == ["T1078", "T1071"]
    assert techs[0]["tactics"] == ["Defense Evasion", "Initial Access"]
    assert techs[1]["tactics"] == ["Command and Control"]


def test_norm_ts_accepts_github_z_suffix():
    assert tc.norm_ts("2026-11-11T06:00:00Z") == "2026-11-11T06:00:00+00:00"


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


def test_malwarebazaar_requires_key_and_maps_samples(monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_KEY", raising=False)
    with pytest.raises(RuntimeError):
        tc.collect_malwarebazaar(days=7)
    monkeypatch.setenv("MALWAREBAZAAR_KEY", "k")
    sha = "a" * 64
    payload = {"query_status": "ok", "data": [
        {"sha256_hash": sha, "first_seen": "2026-11-11 06:00:00", "file_name": "x.exe",
         "file_type": "exe", "signature": "ExampleFamily", "tags": ["loader"]},
        {"sha256_hash": "b" * 64, "first_seen": "2019-01-01 00:00:00", "signature": None},
    ]}
    with mock.patch.object(tc.requests, "post", return_value=FakeResp(payload)) as post:
        out = tc.collect_malwarebazaar(days=36500)
    assert post.call_args.kwargs["data"] == {"query": "get_recent", "selector": "100"}
    assert post.call_args.kwargs["headers"]["Auth-Key"] == "k"
    assert len(out) == 2
    assert out[0]["ioc"] == sha and out[0]["type"] == "malware" and out[0]["severity"] == "high"
    assert out[0]["actor"] == "ExampleFamily" and out[0]["tier"] == "trusted"
    assert out[1]["severity"] == "medium" and out[1]["actor"] == "Unattributed"


def test_malwarebazaar_no_results_is_empty_not_error(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_KEY", "k")
    with mock.patch.object(tc.requests, "post", return_value=FakeResp({"query_status": "no_results"})):
        assert tc.collect_malwarebazaar(days=7) == []
    with mock.patch.object(tc.requests, "post", return_value=FakeResp({"query_status": "unknown_selector"})):
        with pytest.raises(RuntimeError):
            tc.collect_malwarebazaar(days=7)


RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item><title>Critical flaw in ExampleSoft (CVE-2026-5555)</title>
        <link>https://www.cert-in.example/adv/1</link><guid>adv-1</guid>
        <pubDate>Tue, 11 Nov 2026 06:00:00 +0530</pubDate></item>
  <item><title>Old advisory</title><link>https://www.cert-in.example/adv/0</link>
        <guid>adv-0</guid><pubDate>Mon, 01 Jan 2018 00:00:00 +0000</pubDate></item>
</channel></rss>"""


def test_certin_requires_configured_feed(monkeypatch):
    monkeypatch.delenv("CERTIN_FEED_URL", raising=False)
    with pytest.raises(RuntimeError, match="not yet confirmed"):
        tc.collect_certin(days=7)


def test_certin_parses_rss_and_filters_window(monkeypatch):
    monkeypatch.setenv("CERTIN_FEED_URL", "https://feed.example/rss")
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(text=RSS)):
        out = tc.collect_certin(days=36500)
    assert len(out) == 2  # window set wide so both items count; the 2018 item is still parsed
    first = out[0]
    assert first["tier"] == "verified" and first["type"] == "advisory" and first["source"] == tc.CERTIN_SOURCE
    assert first["ioc"] == "CVE-2026-5555"
    assert first["date"] == "2026-11-11T00:30:00+00:00"
    errors, _ = tv.validate(_feed(out))
    assert errors == []


def test_certin_window_excludes_old_items(monkeypatch):
    monkeypatch.setenv("CERTIN_FEED_URL", "https://feed.example/rss")
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(text=RSS)):
        out = tc.collect_certin(days=30)
    assert [i["id"] for i in out] == [out[0]["id"]]
    assert out[0]["ioc"] == "CVE-2026-5555"
    assert not any(i["date"].startswith("2018") for i in out)


def test_mitre_techniques_block_is_checked():
    good = {"id": "T1078", "name": "Valid Accounts", "tactics": ["Initial Access"]}
    errors, _ = tv.validate(_feed([], mitre_techniques=[good]))
    assert errors == []
    errors, _ = tv.validate(_feed([], mitre_techniques=[dict(good, id="T12")]))
    assert any("malformed technique id" in e for e in errors)
    errors, _ = tv.validate(_feed([], mitre_techniques=[dict(good, name="")]))
    assert any("missing name" in e for e in errors)
    errors, _ = tv.validate(_feed([], mitre_techniques=[dict(good, tactics="Initial Access")]))
    assert any("'tactics' must be a list" in e for e in errors)
    errors, _ = tv.validate(_feed([], mitre_techniques="nope"))
    assert any("'mitre_techniques' must be a list" in e for e in errors)


def test_new_source_status_joins_by_name():
    feed = _feed([_good_item(source=tc.FEODO_SOURCE)], sources=[
        {"name": tc.FEODO_SOURCE, "status": "ok", "count": 1},
        {"name": tc.GHSA_SOURCE, "status": "error", "count": 0, "error": "rate limited"},
        {"name": tc.MITRE_SOURCE, "status": "ok", "count": 0},
    ])
    errors, _ = tv.validate(feed)
    assert errors == []


def test_runner_writes_mitre_techniques_only_with_flag(tmp_path, monkeypatch):
    """main() runs every source; here they are stubbed so the test stays offline."""
    monkeypatch.setattr(tc, "SOURCES", [("Stub source", lambda days: [])])
    techs = [{"id": "T1078", "name": "Valid Accounts", "tactics": ["Initial Access"]}]
    monkeypatch.setattr(tc, "collect_mitre_stix", lambda: techs)

    plain = tmp_path / "plain.json"
    with mock.patch.object(sys, "argv", ["x", "--out", str(plain), "--no-news"]):
        tc.main()
    assert "mitre_techniques" not in json.loads(plain.read_text(encoding="utf-8"))

    with_mitre = tmp_path / "mitre.json"
    with mock.patch.object(sys, "argv", ["x", "--out", str(with_mitre), "--mitre", "--no-news"]):
        tc.main()
    feed = json.loads(with_mitre.read_text(encoding="utf-8"))
    assert feed["mitre_techniques"] == techs
    assert any(s["name"] == tc.MITRE_SOURCE and s["status"] == "ok" for s in feed["sources"])
    errors, _ = tv.validate(feed)
    assert errors == []


# ------------------------------------------------------------------ attack news
RSS_NEWS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Edge VPN flaw &amp; exploitation</title><link>https://news.example/a1</link><guid>g1</guid>
<pubDate>Tue, 11 Nov 2026 06:00:00 +0000</pubDate>
<description>&lt;p&gt;Attackers &lt;b&gt;exploit&lt;/b&gt; the flaw.&lt;/p&gt;</description>
<category>Vulnerabilities</category></item>
<item><title>Ancient story</title><link>https://news.example/a0</link><guid>g0</guid>
<pubDate>Mon, 01 Jan 2018 00:00:00 +0000</pubDate></item>
<item><title>No link</title><link>ftp://news.example/x</link><guid>g2</guid>
<pubDate>Tue, 11 Nov 2026 06:00:00 +0000</pubDate></item>
</channel></rss>""".encode("utf-8")

ATOM_NEWS = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>x</title>
<entry><title>Atom story</title><id>urn:a1</id><link rel="alternate" href="https://atom.example/s1"/>
<published>2026-11-11T06:00:00Z</published><summary>Short &amp; plain.</summary>
<category term="Malware"/></entry></feed>"""


def test_news_rss_parses_strips_html_and_filters():
    now = tc.datetime(2026, 11, 12, tzinfo=tc.timezone.utc)
    out = tc.parse_news_xml(RSS_NEWS, "Test feed", "trusted", days=7, now=now)
    assert [a["title"] for a in out] == ["Edge VPN flaw & exploitation"]
    a = out[0]
    assert a["url"] == "https://news.example/a1" and a["source"] == "Test feed" and a["tier"] == "trusted"
    assert a["summary"] == "Attackers exploit the flaw." and a["tags"] == ["Vulnerabilities"]
    assert a["published"] == "2026-11-11T06:00:00+00:00"
    assert a["id"].startswith("NEWS-")


def test_news_atom_parses_alternate_link():
    now = tc.datetime(2026, 11, 12, tzinfo=tc.timezone.utc)
    out = tc.parse_news_xml(ATOM_NEWS, "Atom feed", "verified", days=7, now=now)
    assert len(out) == 1
    assert out[0]["url"] == "https://atom.example/s1" and out[0]["summary"] == "Short & plain."
    assert out[0]["tags"] == ["Malware"]


def test_news_feeds_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.delenv("NEWS_FEEDS", raising=False)
    assert tc.load_news_feeds() == tc.NEWS_FEEDS
    monkeypatch.setenv("NEWS_FEEDS", "Mine|https://x.example/rss|trusted;bad|http://no.example|trusted;Also|https://y.example|nope")
    assert tc.load_news_feeds() == [("Mine", "https://x.example/rss", "trusted")]


def test_build_feed_collects_items_and_articles_and_validates(monkeypatch):
    now_recent = tc.datetime.now(tc.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rss = (f'<rss><channel><item><title>Fresh</title><link>https://news.example/f</link>'
           f'<guid>f</guid><pubDate>{tc.datetime.now(tc.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")}</pubDate>'
           f'</item></channel></rss>').encode()
    with mock.patch.object(tc.requests, "get", return_value=FakeResp(content=rss)):
        feed = tc.build_feed(days=7, sources=[("Stub", lambda d: [])],
                             news_feeds=[("Stub news", "https://news.example/rss", "trusted")])
    assert feed["items"] == []
    assert [a["title"] for a in feed["articles"]] == ["Fresh"]
    assert {s["name"]: s["status"] for s in feed["sources"]} == {"Stub": "ok", "Stub news": "ok"}
    errors, _ = tv.validate(feed)
    assert errors == [], errors


def test_build_feed_records_news_failure_without_inventing_articles(monkeypatch):
    def boom(*a, **k):
        raise tc.requests.ConnectionError("offline")
    monkeypatch.setattr(tc.requests, "get", boom)
    feed = tc.build_feed(days=7, sources=[], news_feeds=[("Down", "https://down.example/rss", "trusted")])
    assert feed["articles"] == []
    assert feed["sources"] == [{"name": "Down", "status": "error", "count": 0, "error": "offline"}]


def test_validator_checks_articles():
    good = {"id": "NEWS-1", "title": "t", "url": "https://x.example/a", "source": "S",
            "published": "2026-11-10T00:00:00+00:00", "tier": "trusted"}
    errors, _ = tv.validate(_feed([], articles=[good]))
    assert errors == []
    errors, _ = tv.validate(_feed([], articles=[dict(good, url="javascript:alert(1)")]))
    assert any("url must be http(s)" in e for e in errors)
    errors, _ = tv.validate(_feed([], articles=[dict(good, published="2026-11-10T00:00:00")]))
    assert any("published is not ISO-8601" in e for e in errors)
    errors, _ = tv.validate(_feed([], articles=[{k: v for k, v in good.items() if k != "source"}]))
    assert any("missing 'source'" in e for e in errors)
    errors, _ = tv.validate(_feed([], articles="nope"))
    assert any("'articles' must be a list" in e for e in errors)

