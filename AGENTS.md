# The Eye — AGENTS.md

Repo: https://github.com/ATSDopi/The-Eye (public, MIT)

## What

Free self-hosted OSINT tool. First module: a username scanner ("Sherlock on
steroids") — 6406 sites merged from the Maigret, WhatsMyName and Sherlock
databases. Inspired by usersearch.ai but 100% free (no paid APIs).

## Stack

- Python 3.14, async `httpx`, `rich` CLI, `beautifulsoup4` for enrichment.
- No build step. Run: `python -m theeye <username>`.
- Windows host, Git Bash shell. Use `PYTHONIOENCODING=utf-8` when piping output.
- Deps: `pip install -r requirements.txt`.

## Layout

- `theeye/engine.py` — async scanner, semaphore concurrency, detection logic
  (`_judge`: status_code / presence+absence strings / error_url redirect).
- `theeye/sitesdb.py` — loads `theeye/data/sites.json`, filters
  (tags/country/nsfw/top-N/include-exclude).
- `theeye/verify.py` — false-positive engine: every "found" hit is re-probed
  with a ghost username (`known_unclaimed` or random). Ghost also "found" ->
  `verified="fp"`; ghost "not_found" -> `verified="confirmed"`. FPs are split
  into a second table, skipped during enrichment, persisted in SQLite.
  `selfcheck` command ghost-probes the whole DB once and caches verdicts to
  `data/site_health.json`; `verify_found` consults the cache first so scans
  verify instantly. `theeye/data/site_health.json` is generated, not committed.
- `theeye/breach.py` — breach aggregator: merges leakcheck/xposedornot/proxynova/
  hudsonrock into one deduped timeline + exposure score (clean→critical).
- `theeye/ip_intel.py` — IP modules: internetdb.shodan.io (ports/CPEs/CVEs,
  free no-key), rdap, ipapi.is geo/ASN/flags, PTR. `theeye ip <ip>`.
- `theeye/phone_intel.py` — offline libphonenumber parse (validity, region,
  carrier, line type). `theeye phone <num>`.
- `theeye/cli.py` also has `dossier <target>`: auto-detects email/ip/phone/
  domain/username and chains the right suites.
- `enrich.py` extracts pivot links (other social profiles) + mailto emails
  from found profile pages -> "Pivots" panel after the results table.
- `theeye/variants.py` — username permutations (sep/common/full modes).
- `theeye/report.py` — self-contained dark HTML report.
- `theeye/db.py` — SQLite history + cases (`theeye.db`, auto-created).
- `theeye/email_intel.py` — free email modules: validate (MX/disposable via
  dns.google), gravatar, protonmail (PKS keyserver), github, twitter + spotify
  registration checks, leakcheck, xposedornot (+ breach-analytics: industries,
  password strength), proxynova (COMB, masked), hudsonrock, intelx (leaks/
  pastes/darknet — needs INTELX_KEY in .env, free tier), darkweb (Ahmia
  .onion search — only via a socks5 Tor proxy).
- `theeye/intelx.py` — Intelligence X search wrapper (search -> poll results).
- `theeye/config.py` — .env loader; keys are NEVER hardcoded/committed
  (.env is gitignored).
- `theeye/phone_intel.py` — libphonenumber offline parse + leakcheck +
  proxynova + intelx on the number.
- `theeye/address_intel.py` — postal address: Nominatim (OSM) + BAN
  (api-adresse.data.gouv.fr, France only).
- `theeye/crypto_intel.py` — `detect_chain()` (btc/eth/ltc/doge/xmr/sol)
  + free explorers: blockcypher (multi-chain), mempool.space +
  blockchain.info (btc), ethplorer (eth + ERC-20 tokens), solana public
  JSON-RPC. Monero: format check only (private ledger).
- `theeye/domain_intel.py` — free domain modules: dns (Google DoH), rdap,
  subdomains (crt.sh + hackertarget fallback), urlscan, wayback (CDX),
  mailsec (SPF/DMARC), ransomware (data.ransomware.live victims.json
  client-side match). Same SiteResult/Status contract as email_intel.
- `theeye/cli.py` — argparse; `theeye <name>` defaults to `scan`;
  `theeye email|domain|ip|phone|address|crypto|breach <x>` run the intel
  suites; `theeye dossier` = TOTAL RESEARCH: positional target
  (auto-detected incl. crypto addresses) or flags --first/--last/--name/
  --username/--email/--phone/--domain/--ip/--address/--crypto —
  generates username candidates from names, scans them all on top-N
  sites, chains every suite, prints an identity graph, and `--html`
  exports a standalone dossier page (render_dossier_html in report.py).
  `selfcheck --unknown` re-probes only sites cached as unknown; `sites`
  stats show the health-cache breakdown.
  `scan --deep` rescans pivot usernames found on profiles (top 100).
  Found-table URLs are OSC8 hyperlinks (ctrl+click opens full URL).
- `start.bat` — Windows interactive menu, or passthrough (`start.bat scan x`).
- `scripts/update_sites.py` — downloads the 3 upstream DBs, normalizes to a
  common schema, dedupes by host+path, writes `theeye/data/sites.json`.
- `theeye/data/sites.json` — generated; schema documented in update_sites.py.

## Commands

- Scan: `python -m theeye scan USER [--top N] [--tags a,b] [--country fr]
  [--nsfw] [--variants sep|common|full] [--no-verify] [--no-enrich]
  [--html|--json F|--csv F] [--case C]`
- Inspect DB: `python -m theeye sites --stats|--tags|--search X`
- History: `python -m theeye history` / `report <id> --format html`
- Refresh DB: `python -m theeye update`

## Conventions

- Site DB is **generated** — don't hand-edit `data/sites.json`, patch
  `scripts/update_sites.py` instead.
- Detection returns Status: found / not_found / unknown (protected, network
  error, ambiguous) / illegal (regex rejected) / skipped.
- Confidence: high (definitive string), medium (status/redirect), low
  (protected or weak).
- Maigret `engine` entries are materialized to plain HTTP at merge time
  (`{urlMain}`/`{urlSubpath}` templates). Entries needing login/activation
  stay `disabled`.

## Status / TODO

Done: merged DB (6406 sites, 5788 enabled), async scan, enrichment,
variants, confidence, filters, **false-positive verification pass**
(ghost-username probes; on a top-150 scan it correctly split 27 "found"
into 11 verified + 16 FP-prone sites like Quora/VK/Yelp/WordPress),
HTML/JSON/CSV export, SQLite history, cases, proxy support, start.bat menu.
Email module done: 7 free sources wired (`theeye email <addr>`).
EmailRep dropped (free API now key-only); pinterest/archive.org probes dead.
Domain module done: 6 free sources (`theeye domain <d>`); crt.sh/wayback are
flaky upstream — subdomains falls back to hackertarget, wayback degrades to
snapshot-availability when CDX is down.
Breach report done: `theeye breach <email>` merges 4 leak sources into a
deduped timeline + severity level + dedicated HTML report. xposedornot added
as 8th email module (13 breaches found where leakcheck saw 5).
Selfcheck done: `theeye selfcheck [--top N]` writes data/site_health.json.
IP module done (`theeye ip`), phone done (`theeye phone`, dep: phonenumbers),
`dossier` meta-command done.

Next: crypto address checks (public explorers), web UI, site-health aware
ranking (auto-deprioritize fp-prone sites in `--top`).
