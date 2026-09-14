# SentinelWatch

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
        WATCH :: CVE & Vulnerability Monitor for Shared Hosting!
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20systemd-orange.svg)](#deploy-with-systemd)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org)
[![Sources](https://img.shields.io/badge/Sources-Tier%201–3-red.svg)](#sources-included)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/BlackRainSentinel/sentinelwatch)

---

I work in the security unit of a hosting company managing 200-300+ shared
hosting servers across cPanel/WHM, DirectAdmin, LiteSpeed, and Apache. Every
CVE batch meant manually cross-checking release notes, RSS feeds, and NVD by
hand across half a dozen vendors — and by the time I noticed, the fleet had
already been exposed for hours.

I built SentinelWatch to do that watching for me: pull from every source that
matters for this stack, dedupe, classify against what's actually running on
the fleet, and only ping me when it's real.

---


## What it does

Self-hosted vulnerability monitoring for the hosting / Linux control-panel
ecosystem. **v3** adds version-aware applicability, alert scoring, split
Telegram channels, collector health/heartbeat, CPE-based NVD queries, gap
collectors (DirectAdmin/CSF/Pure-FTPd/JetBackup/BIND), hosting-KEV, and an
optional Telegram command bot.

```
collectors → normalize → SQLite dedup → classify/score → channel deliver
```

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the public scoring contract.

- **Golden recall** — CISA KEV / hosting-KEV / Tier-1 tracked products always surface
- **Version filter** — `config/fleet_versions.yaml` suppresses non-applicable versions
- **Channels** — `critical` / `wordpress` / `digest` (optional separate chat IDs)
- **Schedules** — fast every 2h (Tier1/2), slow every 12h (Wordfence)
- **Health** — failure streaks, empty-success streaks, stale heartbeat alerts

One collector failing does not stop the run. Nothing is marked seen until
successfully parsed and stored.

---

## Quick Start

```bash
git clone https://github.com/BlackRainSentinel/sentinelwatch.git
cd sentinelwatch

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# edit .env — Telegram (+ optional CRITICAL/WORDPRESS chats), WORDFENCE_API_KEY, SMTP

# review config: sources, fleet_versions.yaml, hosting_kev.yaml, digest_hour_utc
```

Dry run:

```bash
python -m sentinelwatch -v
```

> Requires a small VPS you own (1 vCPU / 1GB RAM is enough). No root needed
> to run the pipeline itself — only the systemd deploy step below uses it.
> **Wordfence v3 requires a free API key** (v2 died 2026-03-09).

---

## Deploy with systemd

```bash
sudo useradd --system --home /opt/sentinelwatch --shell /usr/sbin/nologin sentinelwatch
sudo mkdir -p /opt/sentinelwatch
sudo rsync -a --exclude .venv --exclude data ./ /opt/sentinelwatch/
sudo chown -R sentinelwatch:sentinelwatch /opt/sentinelwatch

sudo -u sentinelwatch bash -c '
  cd /opt/sentinelwatch
  python3 -m venv .venv
  .venv/bin/pip install -e .
  cp -n .env.example .env
'

# edit /opt/sentinelwatch/.env and config/config.yaml

sudo cp systemd/sentinelwatch.service /etc/systemd/system/
sudo cp systemd/sentinelwatch.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelwatch.timer
sudo systemctl start sentinelwatch.service   # optional: run once now
systemctl list-timers | grep sentinelwatch
```

Default timers (v3):

```bash
sudo cp systemd/sentinelwatch-fast.* /etc/systemd/system/
sudo cp systemd/sentinelwatch-slow.* /etc/systemd/system/
sudo cp systemd/sentinelwatch-bot.service /etc/systemd/system/   # optional
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelwatch-fast.timer
sudo systemctl enable --now sentinelwatch-slow.timer
# sudo systemctl enable --now sentinelwatch-bot.service
```

- **fast**: every 2 hours (Tier 1/2)
- **slow**: 04:00 and 16:00 UTC (Wordfence)
- Keep `delivery.digest_hour_utc` at `4` or `16`

---

## Configuration

| Where | What |
|-------|------|
| `config/config.yaml` | Sources, tiers, keywords, email CVSS threshold, digest hour, `taxonomy_extra` |
| `.env` | Telegram, SMTP, `WORDFENCE_API_KEY`, optional NVD / GitHub tokens |

### Delivery rules (v2)

| Channel | When |
|---------|------|
| Telegram (immediate) | `always_alert` / KEV, or critical/high with product match (or Tier ≤2 critical/high) |
| Email | KEV / `always_alert`, or cvss ≥ `email_cvss_threshold` |
| Telegram digest | all pending items, once daily at `digest_hour_utc` |

Medium / low / unknown findings without a product match (and not KEV) go to
the digest only. Alerts show source tier (`T1-official` / `T2-research` /
`T3-aggregator`), KEV flag, CVSS, and matched `vendor:product` ids.

---

## Sources included

Configured out of the box (toggle with `enabled:`):

| Source | Tier | Type |
|--------|------|------|
| CISA KEV | 1 | JSON (cisa.gov + GitHub mirror fallback) |
| NVD API 2.0 (full stack keywords) | 1 | API |
| cPanel release notes + security news | 1 | RSS |
| Apache httpd security page | 1 | HTML |
| Exim security advisories | 1 | HTML |
| AlmaLinux 8/9 errata | 1 | RSS |
| CloudLinux + Imunify360 blogs | 1 | RSS |
| Ubuntu USN | 1 | RSS |
| Debian DSA list | 1 | plaintext |
| LiteSpeed blog | 1 | RSS |
| ClamAV blog | 1 | RSS |
| Dovecot news / SpamAssassin news | 1 | RSS/HTML |
| PowerDNS + MariaDB security pages | 1 | HTML |
| seclists oss-sec (filtered) | 2 | RSS |
| GitHub Security Advisories (scoped) | 2 | API |
| Wordfence Intelligence **v3** | 3 | API (key required) |

DirectAdmin / CSF / Pure-FTPd / JetBackup / ISC BIND have no stable public
security feed confirmed in this build — covered via NVD keywords + KEV.
Add a `feed` / `html` entry in YAML when a vendor publishes one.

---

## Add a new source (no existing code changes)

If the source is RSS/Atom:

```yaml
  - name: my_vendor_sec
    type: feed
    enabled: true
    source_tier: 1
    url: https://vendor.example/security/feed.xml
    default_products: [vendor:product]
    include_keywords: [security, cve, vulnerab]
```

HTML / CVE page:

```yaml
  - name: my_vendor_html
    type: html
    enabled: true
    source_tier: 1
    url: https://vendor.example/security/
    default_products: [vendor:product]
    mode: cve_page
```

Add a tracked product without touching the classifier via `taxonomy_extra`,
or extend `sentinelwatch/taxonomy.py`.

For a new API type: add a module under `sentinelwatch/collectors/`, implement
`collect() -> list[Vulnerability]`, register it in `collectors/__init__.py`.

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

---

## Layout

```
sentinelwatch/
  collectors/     # kev, nvd, feed, html, wordfence v3, github_advisories
  taxonomy.py     # curated vendor:product inventory
  classifier.py   # CPE + word-boundary match + KEV golden rule
  db.py
  models.py       # includes cve_ids, source_tier, in_kev, matched_products
  notifier.py
  pipeline.py
config/config.yaml
systemd/
tests/
```

---

## Requirements

- Python 3.11+
- A small VPS you own (1 vCPU / 1GB RAM is enough)
- systemd (timer-based schedule; no cron)
- Free Wordfence API key if the Wordfence source is enabled

---

## Out of scope

- Web dashboard
- Live inventory sync against a private fleet / AWX
- Employer-internal tooling (never referenced here)
- Generic Linux plumbing daemons with no hosting CVE surface
  (`node_exporter`, `filebeat`, `chronyd`, `NetworkManager`, …)

---

## Disclaimer

Built for monitoring infrastructure you own or are responsible for. The
author isn't responsible for missed alerts, false negatives, or misuse.

---

## Author

**Danial Sobhani** — Linux Security Specialist
Telegram: [@danial_hmt](https://t.me/danial_hmt)
Website: [danialsobhani.ir](https://danialsobhani.ir)

## License

MIT
