<div align="center">

# The Eye

**Free, self-hosted OSINT toolkit — find where a username, email, domain, IP, phone or wallet leaves traces online.**

6 800+ sites scanned · Zero paid APIs · Zero accounts · 100% open source

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org)
[![Sites](https://img.shields.io/badge/Sites-6816-2ea44f.svg)](#the-site-database)
[![API keys required](https://img.shields.io/badge/API%20keys-none%20required-orange.svg)](#optional-free-api-key)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-lightgrey.svg)](#install)

</div>

---

## What is The Eye?

The Eye is an all-in-one OSINT (Open Source Intelligence) reconnaissance tool that runs entirely on your machine, for free. Point it at **one piece of information** — a username, an email, a domain, a phone number, an IP, a postal address or a crypto wallet — and it cross-references it against dozens of public sources to build a complete picture.

Its flagship module is a username scanner often described as *"Sherlock on steroids"*: it merges the five biggest open site databases (**Maigret**, **WhatsMyName**, **Sherlock**, **Social-Analyzer**, **Nexfil**) into a single deduplicated list of **6 800+ sites**, then checks them all asynchronously in seconds.

What makes it different from the tools it was inspired by:

- **Built-in false-positive detection** — every "found" hit is re-probed with a ghost username that cannot exist. If the site still answers "found", the hit is flagged and separated. Most scanners don't do this and flood you with noise.
- **Beyond usernames** — email breach reports, domain recon, IP intelligence, phone parsing, address geocoding and crypto wallet lookups, all in one CLI.
- **`dossier` mode** — give it anything (even just a first + last name) and it chains every relevant module automatically, ending with a correlated identity graph.
- **Truly free** — every module uses free public endpoints. The single optional API key (Intelligence X) has a free tier. No credits, no subscriptions, no SaaS.

## The modules

| Command | Input | What you get |
|---|---|---|
| `scan` | username | Accounts found across 6 800+ sites, with confidence + FP verification |
| `email` | email address | Gravatar profile, ProtonMail/GitHub/Twitter/Spotify registration, 5 leak sources |
| `breach` | email address | Deduplicated breach timeline + exposure score (clean → critical) |
| `domain` | domain | DNS, RDAP registration, subdomains, urlscan, Wayback, SPF/DMARC, ransomware-victim check |
| `ip` | IP address | Open ports, CVEs (Shodan InternetDB), ASN, geo, VPN/Tor flags, PTR |
| `phone` | phone number | Validity, region, carrier, line type + leak coverage |
| `address` | postal address | OSM/Nominatim geocoding + official French BAN match |
| `crypto` | wallet address | Chain auto-detect (BTC/ETH/LTC/DOGE/SOL/XMR), balance + tokens via public explorers |
| `dossier` | **anything** | Auto-detects the input and chains every relevant module + identity graph |

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/ATSDopi/The-Eye.git
cd The-Eye
pip install -r requirements.txt
```

That's it — no build step, no Docker, no database server.

## Quick start

**Windows**: double-click `start.bat` for an interactive menu, or use the CLI directly:

```bash
# Scan a username across every site
python -m theeye johndoe

# Fast scan — only the 500 most popular sites
python -m theeye scan johndoe --top 500

# Full identity report from a single email
python -m theeye dossier someone@example.com --html
```

Every command supports `--html` (standalone dark report), `--json` and `--csv` export.

## Username scanning in depth

```bash
python -m theeye scan <username> [options]
```

| Option | Effect |
|---|---|
| `--top N` | Limit to the N most popular sites |
| `--tags coding,gaming` | Only sites in given categories |
| `--country fr` | Only sites from a country |
| `--nsfw` | Include NSFW sites (excluded by default) |
| `--variants sep\|common\|full` | Also try `john_doe`, `john.doe`, leetspeak… |
| `--deep` | Rescan pivot usernames discovered on found profiles |
| `--case NAME` | Group the scan under a named investigation |
| `--proxy socks5://…` | Route through a proxy / Tor |
| `--no-verify` / `--no-enrich` | Skip FP verification / profile enrichment |
| `--html --json F --csv F` | Export formats |

**How detection works**: each site is checked via status code, presence/absence strings, or redirect matching — the merged Maigret engine definitions are materialized to plain HTTP at build time. Results get a confidence grade (`high` / `medium` / `low`), then the **ghost-username verification pass** re-probes each hit with an impossible name: hits the site can't distinguish go to a separate "likely FP" table and are excluded from enrichment.

**One-time speedup**:

```bash
python -m theeye selfcheck --top 500
```

Ghost-probes every site once and caches reliability verdicts, so later scans verify instantly.

## Email & breach intelligence

```bash
python -m theeye email <address>      # 10+ free modules
python -m theeye breach <address>     # consolidated leak report
```

- **Existence checks**: Gravatar (name, bio, linked accounts), ProtonMail (+ account age via PGP keyserver), GitHub profile, **GitHub commits** (`author-email` search — leaks real names + repos), X/Twitter, Spotify, a **generic registration module** driven by Blackbird's email dataset (each check declares its own endpoint/detection — extensible without code), and an opt-in **SMTP RCPT probe** with catch-all detection (`--smtp`; often blocked on residential port 25).
- **Leak sources**: LeakCheck, XposedOrNot (+ industry/password-strength analytics), ProxyNova COMB (masked credential lines), HudsonRock (infostealer infections), IntelX (leaks/pastes/darknet, free key), Ahmia darkweb search (over Tor). `--breach-only` runs just the leak sources.
- **`breach`** merges everything into one deduplicated timeline — dump filenames like `Houzz.com.rar/x_3.txt [Part 132 of 1025]` normalize to the same breach — then scores exposure from `clean` to `critical`.

## Dossier — one command, total research

```bash
python -m theeye dossier <anything>                          # auto-detect input type
python -m theeye dossier --first Jean --last Dupont          # generates username candidates
python -m theeye dossier --email a@b.c --username jd --phone +33… --crypto 0x…
```

`dossier` runs every relevant suite, scans generated username candidates on top sites, **permutates email addresses** (first+last → `j.dupont@`, `jd@`… tested against leak sources — a hit proves the address exists), cross-checks avatar hashes between profiles and Gravatar, and finishes with an **identity graph**: usernames, names, emails, phones, addresses, wallets, accounts and profile URLs — all correlated in one table (or one `--html` page).

## Optional free API key

Everything above works keyless. To also search **Intelligence X** (leaks, pastes, darknet records — free tier), create a `.env` file:

```
INTELX_KEY=your-free-key   # get one at https://free.intelx.io
```

## The site database

The bundled `sites.json` merges **Maigret** (6 121), **Social-Analyzer** (999), **WhatsMyName** (717), **Sherlock** (482) and **Nexfil** (328), deduplicated by host+path into 6 816 entries — including generic engine support (Discourse, XenForo, MediaWiki, Mastodon, Lemmy, Gitea, phpBB…).

```bash
python -m theeye sites --stats        # database overview
python -m theeye sites --tags         # all filterable categories
python -m theeye sites --search github
python -m theeye update               # re-fetch + merge upstream DBs
```

## Other commands

```bash
python -m theeye history                          # past scans (local SQLite)
python -m theeye report <id> --format html -o out # re-export a past scan
```

## Caveats & responsible use

- Hits marked `?` or `low` confidence can still be false positives — open the URL to confirm. Rows flagged `likely fp` mean the site itself can't tell existing from non-existing accounts.
- Some sites rate-limit aggressively; if you see many `unknown` results, lower `--concurrency` or run `selfcheck`.
- The Eye only queries **public** endpoints — the same ones a browser would hit. **Use it legally and ethically**: OSINT on yourself, consenting targets, or legitimate investigations. You are responsible for complying with applicable laws and each site's terms of service.

## Roadmap

- [ ] Web UI
- [ ] Site-health-aware ranking (auto-deprioritize FP-prone sites in `--top`)
- [x] Username scan across 6 800+ sites with FP verification
- [x] Email, breach, domain, IP, phone, address, crypto modules
- [x] `dossier` cross-module identity graph

## Credits

Site data aggregated from [Maigret](https://github.com/soxoj/maigret), [WhatsMyName](https://github.com/WebBreacher/WhatsMyName), [Sherlock](https://github.com/sherlock-project/sherlock), [Social-Analyzer](https://github.com/qeeqbox/social-analyzer), [Nexfil](https://github.com/thewhiteh4t/nexfil) and [Blackbird](https://github.com/p1ngul1n0/blackbird). Intelligence from free public services: Gravatar, LeakCheck, XposedOrNot, ProxyNova, HudsonRock, crt.sh, urlscan.io, Wayback Machine, Shodan InternetDB, ipapi.is, Nominatim, BAN, mempool.space, Ethplorer, BlockCypher and Intelligence X.

## License

[MIT](LICENSE) — free to use, modify and redistribute.
