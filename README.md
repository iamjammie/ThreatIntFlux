# ThreatIntFlux

**The Edge Before Engagement.** An offline-first threat-intelligence console with a collector that pulls from public feeds and a validator that enforces the data schema.

<!-- suite-nav:start -->
> **Part of the [iamjammie Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)** — open-source, offline-first security tooling and knowledge.
>
> 🧠 [Hunt-Sage](https://github.com/iamjammie/hunt-sage) (knowledge) · 🌊 [FluxHunt](https://github.com/iamjammie/FluxHunt) (wire) · 🖥️ [HostHunt](https://github.com/iamjammie/HostHunt) (box) · 📡 [HostVigil](https://github.com/iamjammie/HostVigil) (fleet) · 🔐 [ADHuntX](https://github.com/iamjammie/ADHuntX) (directory) · 🎯 [Sentinel Matrix](https://github.com/iamjammie/Sentinel-Matrix) (detection coverage) · 🧬 [TTP NEXUS](https://github.com/iamjammie/TTP-Nexus) (frameworks) · 🛡️ **ThreatIntFlux** (threat intel) · 🔦 [Photonwire](https://github.com/iamjammie/PhotonWire) (air gap) · 🛰️ [SPECTRA](https://github.com/iamjammie/SPECTRA---Space-Cyber-Framework) (space)
>
> [Suite hub](https://iamjammie.github.io/FluxHunt/suite.html) · [All projects](https://github.com/iamjammie)
<!-- suite-nav:end -->

- **Console:** `index.html`, a single file with no build step. Dark analyst UI with an intel feed, advanced search with field filters, a MITRE ATT&CK matrix, actor and vulnerability views, IOCs, leak claims, source verification, and an executive briefing you print to PDF.
- **Collector:** `threatintflux_collector.py` writes `threatintflux_feed.json` from public sources.
- **Validator:** `threatintflux_validate.py` checks a feed against the schema. The console runs the same rules on import.

## What is live and what is sample

| Thing | Status |
|---|---|
| Console UI and all views | Working |
| Built-in dataset | **SAMPLE.** Synthetic records tagged `SAMPLE` for exercising the interface. They are not threat intelligence. |
| Live feeds | Only what `threatintflux_collector.py` actually retrieves. A source that fails is reported as an error, and no items are invented to fill the gap. |
| Dark web and leak sites | **Not implemented as crawlers.** The leak view displays claims you import. Treat every listing as unverified. |

The sample dataset uses placeholder actors (`ACTOR-A07`), RFC 5737 documentation IP ranges, and `.example` domains. It names no real organisation as a victim.

## Quick start

```bash
# Console: open index.html in a browser, or serve the folder
python3 -m http.server 8000        # then open http://localhost:8000/

# Collector: pulls live data into threatintflux_feed.json
pip install requests
export THREATFOX_KEY=...           # optional, free key from abuse.ch
export OTX_KEY=...                 # optional, free key from AlienVault OTX
export NVD_KEY=...                 # optional, raises NVD rate limits
export GITHUB_TOKEN=...            # optional, raises the GitHub advisories rate limit
python3 threatintflux_collector.py --days 7
python3 threatintflux_collector.py --days 7 --mitre   # also exports the full ATT&CK matrix

# Validate the result
python3 threatintflux_validate.py threatintflux_feed.json
```

Put `threatintflux_feed.json` beside `index.html` and the console loads it on start. You can also import it from Settings.

## Sources and trust tiers

Every item carries one of four trust tiers. The tier decides how an item may be used.

| Tier | Meaning | Use |
|---|---|---|
| **Verified** | Official government, CERT or standards body | Actionable |
| **Trusted** | Established vendor or community with editorial review | Corroborate before blocking at scale |
| **Unverified** | Claims without independent confirmation, such as forum posts or leak-site listings | Monitor only |
| **Untrusted** | Failed validation or unknown provenance | Excluded from reports |

Collected by the collector:

- CISA Known Exploited Vulnerabilities (verified)
- NVD CVE API 2.0 (verified)
- abuse.ch URLhaus (trusted)
- abuse.ch ThreatFox (trusted, needs a free key)
- AlienVault OTX subscribed pulses (trusted, needs a free key)
- abuse.ch Feodo Tracker botnet C2 blocklist (trusted, no key)
- GitHub Security Advisories (verified, optional token)
- Ransomware leak-site aggregator, ransomware.live (unverified: these are the groups' own claims)
- abuse.ch MalwareBazaar recent samples (trusted, needs a free Auth-Key via `MALWAREBAZAAR_KEY`; the endpoint returns the latest 100 additions)
- CERT-In advisories (verified, RSS 2.0; set `CERTIN_FEED_URL` to the feed you verify, because the public feed URL is not yet confirmed)
- MITRE ATT&CK Enterprise technique list for the matrix (verified reference, `--mitre` only; produces no items)

Listed as reference only and not ingested: the curated OSINT directories on start.me that the console's Source Verification page links to. They are link collections, not feeds.

CERT-In is a verified source. The collector reads an RSS feed you configure with `CERTIN_FEED_URL`. Until that is set, the source reports an error and produces no items. The public feed URL has not been confirmed.

## Browser collector (no Python)

`collector.html` runs the same sources in the browser: open it from the same folder as `index.html` (served over http or https). It collects, validates, and then either downloads `threatintflux_feed.json` or sends the dataset straight to the console in that browser.

- Browsers block many public feeds (CORS). A blocked source shows its error. Enter a CORS proxy you control to reach those sources, and never send API keys through a proxy you do not control.
- Keys are held in the page's memory only. They are never saved.
- The MITRE full matrix export is Python-only (`--mitre`), because the STIX bundle is large.

## Validation

Validation runs in three places:

1. **Collector output** is checked by `threatintflux_validate.py` (schema, enums, ISO-8601 timestamps with a timezone, no future dates, IOC shape, MITRE id format, source status consistent with items, no synthetic items in a live feed).
2. **Browser import** applies the same rules in `index.html` (`validateItems`) and rejects a bad file with the reasons.
3. **CI** (`.github/workflows/validate.yml`) runs the offline test suite in `tests/` and validates the committed fixture feed. The tests cover the parsers with fixture responses, so no network is needed.

```bash
python3 -m pytest tests/ -q
```

## Limitations

- The collector has been tested against fixture responses. Field names come from each provider's documented format, but a live run may still surface format drift. Run the validator after each collection.
- Without `--mitre`, the MITRE matrix uses a built-in subset of techniques. With `--mitre`, the collector exports the full Enterprise list and the matrix uses it.
- The Sources view shows a health line and each source's error from the last run. Sources that fail are never filled with items.
- Charts use Chart.js from a CDN. Without it, the rest of the console still works and charts show a note.
- Severity is the source's rating, not an assessment of impact on your organisation.

## Handling leak and dark web material

Leak listings and forum claims can contain personal data and stolen material. Do not download, republish, or act on a listing as if it were confirmed. Validate with the affected organisation or CERT-In first, and follow your legal and data-protection obligations. The console does not fetch leak content.

## Licence

MIT. See `LICENSE`.
