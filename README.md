# ThreatIntFlux

**The Edge Before Engagement.** An offline-first threat-intelligence console. It works fully from a saved dataset, and when a local companion is running it syncs live intel from public sources, validates it, and turns it into executive and technical reporting.

<!-- suite-nav:start -->
> **Part of the [iamjammie Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)** — open-source, offline-first security tooling and knowledge.
>
> 🧠 [Hunt-Sage](https://github.com/iamjammie/hunt-sage) (knowledge) · 🌊 [FluxHunt](https://github.com/iamjammie/FluxHunt) (wire) · 🖥️ [HostHunt](https://github.com/iamjammie/HostHunt) (box) · 📡 [HostVigil](https://github.com/iamjammie/HostVigil) (fleet) · 🔐 [ADHuntX](https://github.com/iamjammie/ADHuntX) (directory) · 🎯 [Sentinel Matrix](https://github.com/iamjammie/Sentinel-Matrix) (detection coverage) · 🧬 [TTP NEXUS](https://github.com/iamjammie/TTP-Nexus) (frameworks) · 🛡️ **ThreatIntFlux** (threat intel) · 🔦 [Photonwire](https://github.com/iamjammie/PhotonWire) (air gap) · 🛰️ [SPECTRA](https://github.com/iamjammie/SPECTRA---Space-Cyber-Framework) (space)
>
> [Suite hub](https://iamjammie.github.io/FluxHunt/suite.html) · [All projects](https://github.com/iamjammie)
<!-- suite-nav:end -->

## What you get

| Module | What it shows |
|---|---|
| **Executive summary** | Key figures, a threat index (0–100), findings written from the data, recommended actions, the highest-priority items, and tier and severity charts |
| **Threat feed** | Every item with trust tier and source, filterable by field (`severity:critical`, `-term` to exclude) |
| **Attack news** | Recent articles from configured RSS/Atom feeds. Reported, not verified |
| **IOCs** | Indicators classified (IPv4, IPv6, domain, URL, hash, CVE). Export to CSV or a STIX 2.1 indicator bundle |
| **IOAs** | 18 indicators of attack: behaviours to hunt for, mapped to MITRE ATT&CK, with hits and coverage from the current intel |
| **ATT&CK coverage** | Matrix of tactics and techniques, with live counts. Loads the full Enterprise list when the collector exports it |
| **APT tracker** | Actors as attributed by sources: weekly activity, momentum, sectors, regions, techniques, and a profile drawer |
| **Foresight** | Weekly volume with a 4-week projection and band, technique and actor momentum, and scenario sensitivity |
| **Reports** | Executive brief and technical report, both print to PDF. Scope and window options |
| **Sources** | Trust tier for every source, last-sync health, and each failed source's error |
| **Settings** | Connectivity, live sync, feed import and export, sample and clear |

## Offline-first, and what happens online

The console loads nothing from the network. It has no external scripts, fonts or images, and its only requests go to the local companion. The charts are drawn in SVG.

- **Offline (default):** open `index.html`. It loads the saved dataset, or the labelled sample on first run. Every module works.
- **Online with the companion:** run `python3 serve.py`, then open `http://127.0.0.1:8787/`. **Sync live intel** asks the companion to run the collector, and the result replaces the dataset. If a sync returns nothing, for example because every source is down, your current dataset is kept and the reason is shown.

Why a companion? Most public intel feeds block requests from a web page (CORS). The companion runs on your machine, so the browser never contacts the sources, and API keys stay in environment variables on that machine.

```bash
pip install requests
export THREATFOX_KEY=... OTX_KEY=... MALWAREBAZAAR_KEY=... GITHUB_TOKEN=... NVD_KEY=...
export CERTIN_FEED_URL=...        # see the CERT-In note below
python3 serve.py                  # open http://127.0.0.1:8787/
```

Keys are optional; a source without its key shows as an error and is never filled with data. `/api/status` reports which keys are set, never their values.

### Companion security

- Binds to `127.0.0.1` only.
- Serves four fixed files (`index.html`, `collector.html`, `threatintflux_feed.json`, and `/`). Nothing else, so `.git` and source files are not reachable.
- Rejects requests whose `Host` header is not localhost (DNS-rebinding defence).
- Sync requires the header `X-TIF: 1`, which a cross-site page cannot send without a preflight the server never grants.
- Responses carry a Content-Security-Policy that allows only same-origin content.

## Sources and trust tiers

Every item and article carries a trust tier. The tier decides how it may be used.

| Tier | Meaning | Use |
|---|---|---|
| **Verified** | Official government, CERT or standards body | Actionable |
| **Trusted** | Established vendor or community with editorial review | Corroborate before blocking at scale |
| **Unverified** | Claims without independent confirmation, such as leak-site listings | Monitor only |
| **Untrusted** | Failed validation or unknown provenance | Excluded from reports |

Collected by the collector:

- CISA Known Exploited Vulnerabilities (verified)
- NVD CVE API 2.0 (verified)
- GitHub Security Advisories (verified, optional token)
- CERT-In advisories (verified, RSS, see below)
- abuse.ch URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker (trusted)
- AlienVault OTX subscribed pulses (trusted)
- Ransomware leak-site aggregator, ransomware.live (unverified: these are the groups' own claims)
- Attack news: CISA advisories, The Hacker News, BleepingComputer (RSS, see below)
- MITRE ATT&CK Enterprise technique list, with `--mitre` (verified reference; produces no items)

Listed as reference only, not ingested: the curated OSINT directories on start.me.

### Things to confirm before relying on them

- **CERT-In.** The public advisory feed URL has not been confirmed. Until you set `CERTIN_FEED_URL` to a feed you have checked, that source reports an error and produces no items.
- **News feed URLs.** The three RSS URLs are not verified against the live sites. Override them with `NEWS_FEEDS`, one `name|https-url|tier` entry per `;` separated item.
- **MalwareBazaar** returns the latest 100 additions, so a busy period has more samples than the collector sees.
- **Live behaviour.** The collectors were tested against fixtures and mocked responses. Field names come from each provider's documented format. Run a sync once with network access and check the Sources view.

## Command-line collector

```bash
python3 threatintflux_collector.py --days 7                # feed items and articles
python3 threatintflux_collector.py --days 7 --mitre        # also the full ATT&CK matrix
python3 threatintflux_collector.py --days 7 --no-news      # skip the news feeds
python3 threatintflux_validate.py threatintflux_feed.json  # check any feed against the schema
```

The collector writes `threatintflux_feed.json`. Place it beside `index.html` and the console loads it on start.

## Foresight: method and limits

Projections are a least-squares trend on the last 8 weekly counts. The band is ±1.96 × the residual standard error. The module shows direction and rough scale for capacity planning. It does **not** predict specific attacks, and it assumes the recent trend continues. Source reporting changes can move the trend without any change in real activity. With fewer than three weeks of dated items it says so instead of projecting.

## IOAs

The 18 IOAs describe behaviours to hunt for, with the telemetry each needs and the ATT&CK technique it maps to. They are descriptions, not detection code. Adapt them to your own logging and rule language.

## Validation

Validation runs in three places, with the same rules:

1. **Collector output** is checked by `threatintflux_validate.py`: schema, enums, ISO-8601 timestamps with a timezone, no future dates, IOC shape, MITRE id format, source status consistent with items and articles, no synthetic items in a live feed, and the optional technique and article blocks.
2. **Browser import and sync** apply the same rules in `index.html` (`validateItems`, `validateArticles`) and reject a bad feed with the reasons.
3. **CI** (`.github/workflows/validate.yml`) runs the offline test suite and validates the committed fixture feed.

```bash
python3 -m pytest tests/ -q
```

The tests run offline. They cover the parsers with fixtures, the companion over real local HTTP with the collector stubbed, the validator rules, and the console: that its script parses, that it loads nothing from the network, and that every collector source name appears in the console.

## Limitations

- Live sources have not been checked against the live services from the development environment. Check each source once with network access.
- The browser collector page (`collector.html`) reaches sources only if they allow browser requests, or through a CORS proxy you control. The companion is the reliable route.
- The sample dataset is synthetic. Its actors, families, articles and sources are placeholders and are labelled SAMPLE everywhere they appear, including in exports and reports.
- Severity is the source's rating, not an assessment of impact on your organisation.
- Actor names are attributions made by sources. They are claims, and reports say so.

## Handling leak and dark web material

Leak listings and forum claims can contain personal data and stolen material. Do not download, republish, or act on a listing as if it were confirmed. Validate with the affected organisation or CERT-In first, and follow your legal and data-protection obligations. The console and the collectors do not fetch leak content or crawl the dark web; leak-site data is limited to listing metadata from an aggregator, and every such item is unverified.

## Files

- `index.html`: the console (offline, single file)
- `serve.py`: local companion for live sync
- `threatintflux_collector.py`: collectors and feed builder
- `threatintflux_validate.py`: schema validator
- `collector.html`: browser-only collector page (optional)
- `tests/`: offline test suite
- `tests/fixtures/feed_sample.json`: synthetic fixture feed

## Licence

MIT. See `LICENSE`.
