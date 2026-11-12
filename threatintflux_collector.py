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
import hashlib
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

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
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
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
MITRE_SOURCE = "MITRE ATT&CK (STIX 2.1)"


def tactic_display(kebab):
    """'command-and-control' -> 'Command and Control', matching the console's TACTICS names."""
    words = [w.capitalize() for w in kebab.split("-")]
    return " ".join("and" if w == "And" else w for w in words)


def collect_mitre_stix():
    """Full Enterprise ATT&CK technique list for the console matrix (exported with --mitre).

    Returns [{"id", "name", "tactics": [display names]}]. Revoked and deprecated techniques are skipped.
    This produces no intel items; it only feeds the matrix.
    """
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
                              "tactics": [tactic_display(p["phase_name"]) for p in o.get("kill_chain_phases", [])]})
    return techs


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


# ---------------------------------------------------------------- Ransomware leak-site aggregator (unverified claims)
RANSOM_SOURCE = "Ransomware leak-site aggregator"


def collect_ransomware_live(days):
    """Victim listings posted by extortion groups on their leak sites.

    These are the groups' own claims. Nothing here is confirmed by the victim, so every item is
    'unverified'. Only the listing metadata is kept; no leaked files are fetched.
    """
    r = requests.get("https://api.ransomware.live/v2/recentvictims", timeout=TIMEOUT,
                     headers={"User-Agent": UA})
    r.raise_for_status()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for v in r.json() or []:
        when = norm_ts(v.get("discovered") or v.get("published") or v.get("attackdate"))
        if not when or datetime.fromisoformat(when) < cutoff:
            continue
        group = v.get("group_name") or "unknown group"
        victim = v.get("post_title") or "undisclosed victim"
        digest = hashlib.sha1(f"{group}|{victim}|{when}".encode("utf-8")).hexdigest()[:16]
        country = v.get("country") or "unknown"
        out.append(item(
            id=f"RANSOM-{digest}", title=f"Leak-site claim: {group} lists {victim}",
            type="leak", severity="high", tier="unverified", source=RANSOM_SOURCE,
            actor=group, region=country, date=when,
            summary=f"Claim posted by {group}; not confirmed by the victim. Country: {country}.",
        ))
    return out


# ---------------------------------------------------------------- abuse.ch Feodo Tracker (trusted)
FEODO_SOURCE = "abuse.ch Feodo Tracker"


def collect_feodo(days):
    """Botnet command-and-control servers from the Feodo Tracker IP blocklist. No key required."""
    r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=TIMEOUT,
                     headers={"User-Agent": UA})
    r.raise_for_status()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for e in r.json() or []:
        ip = str(e.get("ip_address", "")).strip()
        when = norm_ts(e.get("last_online") or e.get("first_seen"))
        if not ip or not when or datetime.fromisoformat(when) < cutoff:
            continue
        malware = e.get("malware") or "unknown"
        port = e.get("port")
        status = str(e.get("status", "unknown")).lower()
        out.append(item(
            id=f"FEODO-{ip}-{port}", title=f"{malware} botnet C2 {ip}:{port}",
            type="ioc", severity="high" if status == "online" else "medium", tier="trusted",
            source=FEODO_SOURCE, actor=malware, ioc=ip, date=when,
            region=e.get("country") or "Global",
            summary=f"Status: {status}. AS: {e.get('as_name') or 'unknown'}. "
                    f"Hostname: {e.get('hostname') or 'none'}.",
        ))
    return out


# ---------------------------------------------------------------- GitHub Security Advisories (verified)
GHSA_SOURCE = "GitHub Security Advisories"


def collect_ghsa(days):
    """Maintainer-published advisories for open-source packages.

    Set GITHUB_TOKEN to raise the rate limit (unauthenticated requests are limited to 60 an hour).
    """
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get("https://api.github.com/advisories", timeout=TIMEOUT, headers=headers,
                     params={"per_page": 100, "sort": "published", "direction": "desc"})
    r.raise_for_status()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for a in r.json() or []:
        when = norm_ts(a.get("published_at"))
        if not when or datetime.fromisoformat(when) < cutoff:
            continue
        pkgs = sorted({f"{v['package']['ecosystem']}/{v['package']['name']}"
                       for v in a.get("vulnerabilities") or [] if v.get("package")})
        cve = a.get("cve_id") or ""
        out.append(item(
            id=f"GHSA-{a['ghsa_id']}", title=f"{cve or a['ghsa_id']}: {a.get('summary', '')}".strip(": "),
            type="vuln", severity=SEV_MAP.get(str(a.get("severity", "")).lower(), "medium"),
            tier="verified", source=GHSA_SOURCE, ioc=cve, date=when,
            summary=(a.get("description") or a.get("summary") or "")[:500]
                    + (f" Packages: {', '.join(pkgs)}." if pkgs else ""),
        ))
    return out


# ---------------------------------------------------------------- abuse.ch MalwareBazaar (trusted, needs Auth-Key)
MB_SOURCE = "abuse.ch MalwareBazaar"


def collect_malwarebazaar(days):
    """The 100 most recent samples added to MalwareBazaar. Needs a free Auth-Key.

    The endpoint returns only the latest 100 additions, so a busy period can have more
    samples than this collector sees.
    """
    key = os.environ.get("MALWAREBAZAAR_KEY")
    if not key:
        raise RuntimeError("MALWAREBAZAAR_KEY not set (free key from abuse.ch)")
    r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "100"},
                      headers={"Auth-Key": key, "User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    body = r.json()
    status = body.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise RuntimeError(f"MalwareBazaar query_status: {status}")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for s in body.get("data") or []:
        sha = str(s.get("sha256_hash") or "").lower()
        when = norm_ts(s.get("first_seen"))
        if not sha or not when or datetime.fromisoformat(when) < cutoff:
            continue
        sig = s.get("signature") or ""
        tags = s.get("tags") or []
        out.append(item(
            id=f"MALBAZ-{sha}", title=f"{sig or 'unknown family'} sample: {s.get('file_name') or sha[:12]}",
            type="malware", severity="high" if sig else "medium", tier="trusted", source=MB_SOURCE,
            actor=sig or "Unattributed", ioc=sha, date=when,
            summary=f"File type: {s.get('file_type') or 'unknown'}. Tags: {', '.join(tags) or 'none'}.",
        ))
    return out


# ---------------------------------------------------------------- CERT-In advisories (verified, feed URL set explicitly)
CERTIN_SOURCE = "CERT-In (India)"
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}")


def collect_certin(days):
    """Advisories from a CERT-In RSS 2.0 feed.

    The public feed URL has not been confirmed, so it must be set explicitly with CERTIN_FEED_URL.
    Until then this source reports an error and produces no items.
    """
    url = os.environ.get("CERTIN_FEED_URL")
    if not url:
        raise RuntimeError("CERTIN_FEED_URL not set (CERT-In feed URL not yet confirmed)")
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    root = ET.fromstring(r.text.encode("utf-8"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for el in root.iter("item"):
        title = (el.findtext("title") or "").strip()
        link = (el.findtext("link") or "").strip()
        guid = (el.findtext("guid") or link or title).strip()
        if not title:
            continue
        try:
            when = parsedate_to_datetime(el.findtext("pubDate") or "")
        except (TypeError, ValueError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when < cutoff:
            continue
        cves = CVE_IN_TEXT.findall(title)
        out.append(item(
            id=f"CERTIN-{hashlib.sha1(guid.encode('utf-8')).hexdigest()[:16]}", title=title,
            type="advisory", severity="medium", tier="verified", source=CERTIN_SOURCE,
            ioc=cves[0] if cves else "", date=when.astimezone(timezone.utc).isoformat(timespec="seconds"),
            summary=f"Advisory link: {link or 'none'}",
        ))
    return out


# ---------------------------------------------------------------- Runner
SOURCES = [
    ("CISA Known Exploited Vulnerabilities", collect_cisa_kev),
    ("NVD (NIST) CVE API 2.0", collect_nvd),
    ("abuse.ch URLhaus", collect_urlhaus),
    ("abuse.ch ThreatFox", collect_threatfox),
    ("AlienVault OTX", collect_otx),
    (RANSOM_SOURCE, collect_ransomware_live),
    (FEODO_SOURCE, collect_feodo),
    (GHSA_SOURCE, collect_ghsa),
    (MB_SOURCE, collect_malwarebazaar),
    (CERTIN_SOURCE, collect_certin),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="threatintflux_feed.json")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--mitre", action="store_true",
                    help="also export the full ATT&CK technique list for the console matrix")
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

    mitre_techniques = None
    if args.mitre:
        try:
            mitre_techniques = collect_mitre_stix()
            status.append({"name": MITRE_SOURCE, "status": "ok", "count": 0, "error": None})
            print(f"[ok]    {MITRE_SOURCE}: {len(mitre_techniques)} techniques")
        except Exception as e:
            status.append({"name": MITRE_SOURCE, "status": "error", "count": 0, "error": str(e)[:300]})
            print(f"[error] {MITRE_SOURCE}: {e}", file=sys.stderr)

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
    if mitre_techniques is not None:
        feed["mitre_techniques"] = mitre_techniques
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2)
    ok = sum(1 for s in status if s["status"] == "ok")
    print(f"\nWrote {len(feed['items'])} items from {ok}/{len(status)} sources to {args.out}")


if __name__ == "__main__":
    main()
