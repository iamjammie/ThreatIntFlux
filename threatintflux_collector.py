#!/usr/bin/env python3
"""
ThreatIntFlux collector.

Pulls intelligence from public sources and writes threatintflux_feed.json, which the
ThreatIntFlux console (index.html) loads from the same folder or via Settings > Import.

Only sources that return real data are marked "ok". Failures are recorded with the
error, never filled with invented items.

Usage:
    pip install requests
    export THREATFOX_KEY=...      # optional, free key from abuse.ch
    export OTX_KEY=...            # optional, free key from AlienVault OTX
    python3 threatintflux_collector.py --out threatintflux_feed.json --days 7
"""
import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import requests

UA = "ThreatIntFlux-Collector/3.0 (analyst console; contact: set-your-contact)"
TIMEOUT = 40
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_ts(value):
    """Normalise the timestamp shapes these feeds use to ISO-8601 with UTC offset.

    Accepts: '2026-11-11T06:00:00+00:00', '2026-11-11 06:00:00', '2026-11-11 06:00:00 UTC',
    '2026-11-11T06:00:00.123456' (naive, treated as UTC), and date-only '2026-11-10'.
    Returns None when the value cannot be parsed; callers fall back to now_iso().
    """
    if not value:
        return None
    s = str(value).strip()
    if s.endswith(" UTC"):
        s = s[:-4].strip()
    s = s.replace(" ", "T", 1) if "T" not in s and " " in s else s
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def item(**kw):
    base = {
        "id": "", "title": "", "type": "vuln", "severity": "medium", "tier": "trusted",
        "source": "", "actor": "Unattributed", "sector": "Unspecified", "region": "Global",
        "ioc": "", "date": now_iso(), "summary": "", "mitre": [], "synthetic": False,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------- CISA KEV (verified)
def collect_cisa_kev(days):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for v in r.json().get("vulnerabilities", []):
        added = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        if added < cutoff:
            continue
        ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        out.append(item(
            id=f"CISA-{v['cveID']}", title=f"{v['cveID']}: {v['vulnerabilityName']}",
            type="vuln", severity="critical" if ransom else "high", tier="verified",
            source="CISA Known Exploited Vulnerabilities", ioc=v["cveID"], date=added.isoformat(),
            sector="Multiple", region="Global",
            summary=f"{v.get('vendorProject','')} {v.get('product','')}. {v.get('shortDescription','')} "
                    f"Required action: {v.get('requiredAction','')}",
            mitre=["T1190"],
        ))
    return out


# ---------------------------------------------------------------- NVD CVE API 2.0 (verified)
def collect_nvd(days):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 120))  # NVD limits windows to 120 days
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    key = os.environ.get("NVD_KEY")
    headers = {"User-Agent": UA}
    if key:
        headers["apiKey"] = key
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params,
                     headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for w in r.json().get("vulnerabilities", []):
        c = w["cve"]
        metrics = c.get("metrics", {})
        score, sev = None, "medium"
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                d = metrics[k][0]["cvssData"]
                score = d.get("baseScore")
                sev = (d.get("baseSeverity") or metrics[k][0].get("baseSeverity", "medium")).lower()
                break
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        out.append(item(
            id=f"NVD-{c['id']}", title=f"{c['id']} (CVSS {score if score is not None else 'n/a'})",
            type="vuln", severity=SEV_MAP.get(sev, "medium"), tier="verified", source="NVD (NIST) CVE API 2.0",
            ioc=c["id"], date=c.get("published", now_iso()), summary=desc[:600], mitre=["T1190"],
        ))
    return out


# ---------------------------------------------------------------- MITRE ATT&CK STIX (verified reference)
def collect_mitre_stix():
    """Returns technique metadata used to validate the console's matrix. Stored in feed meta."""
    url = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
           "enterprise-attack/enterprise-attack.json")
    r = requests.get(url, timeout=120, headers={"User-Agent": UA})
    r.raise_for_status()
    techs = []
    for o in r.json().get("objects", []):
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            ext = next((e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
            if ext:
                techs.append({"id": ext["external_id"], "name": o["name"],
                              "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])]})
    return techs  # returned for matrix export; not converted to intel items


# ---------------------------------------------------------------- URLhaus recent CSV (trusted)
def collect_urlhaus(days):
    r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
    out = []
    # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    for row in csv.reader(io.StringIO("\n".join(lines))):
        if len(row) < 7:
            continue
        uid, dateadded, url, status, _last_online, threat, tags = row[:7]
        out.append(item(
            id=f"URLHAUS-{uid}", title=f"Malware distribution URL ({threat or 'unknown'})",
            type="ioc", severity="high" if status == "online" else "medium", tier="trusted",
            source="abuse.ch URLhaus", ioc=url, date=norm_ts(dateadded) or now_iso(),
            summary=f"Status: {status}. Tags: {tags}", mitre=["T1105"],
        ))
    return out[:500]


# ---------------------------------------------------------------- ThreatFox (trusted, needs Auth-Key)
def collect_threatfox(days):
    key = os.environ.get("THREATFOX_KEY")
    if not key:
        raise RuntimeError("THREATFOX_KEY not set (free key from abuse.ch)")
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": min(days, 7)},
                      headers={"Auth-Key": key, "User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json().get("data") or []
    out = []
    for d in data[:500]:
        out.append(item(
            id=f"TFOX-{d.get('id')}", title=f"{d.get('malware_printable','unknown')} IOC ({d.get('ioc_type','')})",
            type="ioc", severity="high" if d.get("confidence_level", 0) >= 75 else "medium", tier="trusted",
            source="abuse.ch ThreatFox", actor=d.get("malware_printable", "Unattributed"),
            ioc=d.get("ioc", ""), date=norm_ts(d.get("first_seen_utc")) or now_iso(),
            summary=f"Threat type: {d.get('threat_type','')}. Tags: {', '.join(d.get('tags') or [])}",
        ))
    return out


# ---------------------------------------------------------------- AlienVault OTX (trusted, needs API key)
def collect_otx(days):
    key = os.environ.get("OTX_KEY")
    if not key:
        raise RuntimeError("OTX_KEY not set (free key from AlienVault OTX)")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                     params={"modified_since": since, "limit": 50},
                     headers={"X-OTX-API-KEY": key, "User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for p in r.json().get("results", []):
        tags = p.get("tags") or []
        out.append(item(
            id=f"OTX-{p.get('id')}", title=p.get("name", "OTX pulse"), type="campaign", severity="medium",
            tier="trusted", source="AlienVault OTX", actor=p.get("adversary") or "Unattributed",
            date=norm_ts(p.get("modified")) or now_iso(),
            summary=(p.get("description") or "")[:500], mitre=[],
        ))
        for ind in (p.get("indicators") or [])[:20]:
            out.append(item(
                id=f"OTX-{p.get('id')}-{ind.get('id')}", title=f"{ind.get('type','IOC')} from pulse",
                type="ioc", severity="medium", tier="trusted", source="AlienVault OTX",
                ioc=ind.get("indicator", ""), date=norm_ts(ind.get("created")) or now_iso(),
                summary=p.get("name", ""),
            ))
    return out


# ---------------------------------------------------------------- Runner
SOURCES = [
    ("CISA Known Exploited Vulnerabilities", collect_cisa_kev),
    ("NVD (NIST) CVE API 2.0", collect_nvd),
    ("abuse.ch URLhaus", collect_urlhaus),
    ("abuse.ch ThreatFox", collect_threatfox),
    ("AlienVault OTX", collect_otx),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="threatintflux_feed.json")
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args()

    items, status = [], []
    for name, fn in SOURCES:
        try:
            got = fn(args.days)
            items.extend(got)
            status.append({"name": name, "status": "ok", "count": len(got), "error": None})
            print(f"[ok]    {name}: {len(got)} items")
        except Exception as e:  # record, never fabricate
            status.append({"name": name, "status": "error", "count": 0, "error": str(e)[:300]})
            print(f"[error] {name}: {e}", file=sys.stderr)

    # de-duplicate by id, keep latest
    dedup = {}
    for it in items:
        dedup[it["id"]] = it
    feed = {
        "generated_at": now_iso(),
        "mode": "live",
        "window_days": args.days,
        "sources": status,
        "items": list(dedup.values()),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2)
    ok = sum(1 for s in status if s["status"] == "ok")
    print(f"\nWrote {len(feed['items'])} items from {ok}/{len(status)} sources to {args.out}")


if __name__ == "__main__":
    main()
