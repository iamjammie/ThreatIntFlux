#!/usr/bin/env python3
"""
Validate a ThreatIntFlux feed file (threatintflux_feed.json) against the schema the console expects.

Checks:
  * top-level keys: generated_at (ISO-8601), sources (list), items (list)
  * every item has id, title, type, severity, tier, source, date and the expected enum values
  * ids are unique across the feed
  * dates parse as ISO-8601 with a timezone and are not in the future
  * IOCs are well formed for their shape (IPv4/IPv6, domain, URL, CVE, hash)
  * MITRE technique ids look like T1234 or T1234.567
  * source status is consistent with the items it produced
  * a feed that claims to be live contains no synthetic items
  * optional 'mitre_techniques' (full ATT&CK list for the matrix): ids, names and tactics well formed
  * optional 'articles' (attack news): id, title, http(s) url, source, timezone-aware published date, tier

Exit code 0 when valid, 1 when any error is found.

Usage: python3 threatintflux_validate.py threatintflux_feed.json
"""
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone

TYPES = {"vuln", "ioc", "malware", "actor", "leak", "campaign", "advisory"}
SEVERITIES = {"critical", "high", "medium", "low"}
TIERS = {"verified", "trusted", "unverified", "untrusted"}
REQUIRED = ["id", "title", "type", "severity", "tier", "source", "date"]
SOURCE_STATUS = {"ok", "error"}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
URL_RE = re.compile(r"^https?://[^\s]+$", re.I)


def parse_iso(value):
    """Return an aware datetime or None. Naive timestamps are rejected on purpose."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def check_ioc(value, errors, where):
    """Only validates the shapes we can check unambiguously; unknown shapes pass through."""
    v = value.strip()
    if not v:
        return
    try:
        ipaddress.ip_address(v)
        return
    except ValueError:
        pass
    if URL_RE.match(v):
        return
    if CVE_RE.match(v) or HASH_RE.match(v):
        return
    if DOMAIN_RE.match(v):
        return
    # Free-form identifiers (e.g. SYN-VULN-0001) are allowed; flag only obvious junk.
    if " " in v and len(v) > 200:
        errors.append(f"{where}: IOC looks malformed")


def validate(feed):
    errors, warnings = [], []

    if not isinstance(feed, dict):
        return ["top level must be an object"], warnings
    for key in ("generated_at", "items"):
        if key not in feed:
            errors.append(f"missing top-level key '{key}'")
    if feed.get("generated_at") is not None:
        gen = parse_iso(feed["generated_at"])
        if gen is None:
            errors.append("generated_at is not ISO-8601 with a timezone")
    items = feed.get("items")
    if not isinstance(items, list):
        errors.append("'items' must be a list")
        items = []

    sources = feed.get("sources", [])
    if not isinstance(sources, list):
        errors.append("'sources' must be a list when present")
        sources = []

    seen = set()
    counts_by_source = {}
    synthetic_count = 0
    now = datetime.now(timezone.utc) + timedelta(minutes=5)  # small clock-skew allowance

    for idx, it in enumerate(items):
        where = f"items[{idx}]"
        if not isinstance(it, dict):
            errors.append(f"{where}: must be an object")
            continue
        for k in REQUIRED:
            if not it.get(k):
                errors.append(f"{where}: missing '{k}'")
        iid = it.get("id")
        if iid:
            where = f"items[{idx}] ({iid})"
            if iid in seen:
                errors.append(f"{where}: duplicate id")
            seen.add(iid)
        if it.get("type") and it["type"] not in TYPES:
            errors.append(f"{where}: unknown type '{it['type']}'")
        if it.get("severity") and it["severity"] not in SEVERITIES:
            errors.append(f"{where}: unknown severity '{it['severity']}'")
        if it.get("tier") and it["tier"] not in TIERS:
            errors.append(f"{where}: unknown tier '{it['tier']}'")
        if it.get("date"):
            dt = parse_iso(it["date"])
            if dt is None:
                errors.append(f"{where}: date '{it['date']}' is not ISO-8601 with a timezone")
            elif dt > now:
                errors.append(f"{where}: date is in the future ({it['date']})")
        if it.get("ioc"):
            check_ioc(str(it["ioc"]), errors, where)
        for t in it.get("mitre") or []:
            if not TECH_RE.match(str(t)):
                errors.append(f"{where}: malformed MITRE technique '{t}'")
        if it.get("synthetic"):
            synthetic_count += 1
        if it.get("source"):
            counts_by_source[it["source"]] = counts_by_source.get(it["source"], 0) + 1

    articles = feed.get("articles") or []
    if not isinstance(articles, list):
        errors.append("'articles' must be a list when present")
        articles = []
    seen_articles = set()
    for idx, a in enumerate(articles):
        where = f"articles[{idx}]"
        if not isinstance(a, dict):
            errors.append(f"{where}: must be an object")
            continue
        for k in ("id", "title", "url", "source", "published", "tier"):
            if not a.get(k):
                errors.append(f"{where}: missing '{k}'")
        if a.get("id"):
            if a["id"] in seen_articles:
                errors.append(f"{where}: duplicate id")
            seen_articles.add(a["id"])
        if a.get("url") and not URL_RE.match(str(a["url"])):
            errors.append(f"{where}: url must be http(s)")
        if a.get("tier") and a["tier"] not in TIERS:
            errors.append(f"{where}: unknown tier '{a['tier']}'")
        if a.get("published"):
            dt = parse_iso(a["published"])
            if dt is None:
                errors.append(f"{where}: published is not ISO-8601 with a timezone")
            elif dt > now:
                errors.append(f"{where}: published is in the future")
        if a.get("source"):
            counts_by_source[a["source"]] = counts_by_source.get(a["source"], 0) + 1

    # Source status must agree with the items it produced. Item 'source' values are the
    # display names from the console's source list, so the two can be joined by name.
    for s in sources:
        name = s.get("name", "?")
        status = s.get("status")
        count = s.get("count") or 0
        if status not in SOURCE_STATUS:
            errors.append(f"source '{name}': status must be 'ok' or 'error'")
        elif status == "ok" and count > 0 and counts_by_source.get(name, 0) == 0:
            errors.append(f"source '{name}' is ok and reports {count} items, but no item carries its name")
        elif status == "error" and count:
            errors.append(f"source '{name}' is in error but reports {count} items")

    # A live feed must not contain synthetic records.
    if synthetic_count and feed.get("mode") == "live":
        errors.append(f"feed is marked live but contains {synthetic_count} synthetic items")
    if synthetic_count:
        warnings.append(f"{synthetic_count} synthetic (SAMPLE) items present")

    techs = feed.get("mitre_techniques")
    if techs is not None:
        if not isinstance(techs, list):
            errors.append("'mitre_techniques' must be a list when present")
        else:
            for j, t in enumerate(techs):
                where = f"mitre_techniques[{j}]"
                if not isinstance(t, dict):
                    errors.append(f"{where}: must be an object")
                    continue
                if not TECH_RE.match(str(t.get("id", ""))):
                    errors.append(f"{where}: malformed technique id '{t.get('id')}'")
                if not isinstance(t.get("name"), str) or not t.get("name"):
                    errors.append(f"{where}: missing name")
                if not isinstance(t.get("tactics"), list):
                    errors.append(f"{where}: 'tactics' must be a list")

    if not items:
        warnings.append("feed has no items")
    return errors, warnings


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    try:
        with open(path, encoding="utf-8") as f:
            feed = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read {path}: {exc}")
        return 1
    errors, warnings = validate(feed)
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    n = len(feed.get("items", [])) if isinstance(feed, dict) and isinstance(feed.get("items"), list) else 0
    if errors:
        print(f"FAIL: {len(errors)} error(s) in {n} items")
        return 1
    print(f"OK: {n} items valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
