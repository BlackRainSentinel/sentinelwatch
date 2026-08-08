# SentinelWatch

Self-hosted vulnerability monitoring for shared hosting stacks (cPanel/WHM,
DirectAdmin, LiteSpeed, Apache, Exim, AlmaLinux, CloudLinux, Ubuntu, MariaDB,
OpenSSL, PHP, WordPress).

Pulls from multiple public sources, deduplicates in SQLite, classifies by
category / severity / fleet match, and alerts over Telegram and email.

## How it works

```
collectors  →  normalize  →  SQLite dedup  →  classify  →  deliver
   │                              │              │            │
 feed / NVD / WF / GHSA     source:id once   tier+fleet   TG / email / digest
```

- **Immediate Telegram** — `critical` / `high`, or any `fleet_match`
- **Email** — CVSS ≥ threshold (default 9.0) **or** `fleet_match`
- **Daily Telegram digest** — everything else, once per day at `digest_hour_utc`
  (must match a timer run hour or it never fires)

One collector failing does not stop the run. Nothing is marked seen until it
is successfully parsed and stored.

## Requirements

- Python 3.11+
- A small VPS you own (1 vCPU / 1GB RAM is enough)
- systemd (timer-based schedule; no cron)

## Setup

```bash
git clone https://github.com/BlackRainSentinel/sentinelwatch.git
cd sentinelwatch

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# edit .env — Telegram + SMTP + optional NVD_API_KEY / GITHUB_TOKEN

# review config/config.yaml — fleet_software, sources, digest_hour_utc
```

Dry run:

```bash
python -m sentinelwatch -v
```

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

Default timer: **04:00 and 16:00 UTC**, with up to 5 minutes randomized delay.
Keep `delivery.digest_hour_utc` at `4` or `16`.

## Configuration

| Where | What |
|-------|------|
| `config/config.yaml` | Sources, keywords, fleet list, email CVSS threshold, digest hour |
| `.env` | Telegram bot token/chat, NVD API key, SMTP, optional GitHub token |

### Delivery rules (v1)

| Channel | When |
|---------|------|
| Telegram (immediate) | severity ∈ {critical, high} **or** fleet_match |
| Email | cvss ≥ `email_cvss_threshold` **or** fleet_match |
| Telegram digest | all pending items, once daily at `digest_hour_utc` |

Medium / low / unknown findings without a fleet match go to the digest only.

## Sources included

Configured out of the box (toggle with `enabled:`):

| Source | Type |
|--------|------|
| NVD API 2.0 (stack keywords) | API |
| Wordfence Threat Intel production JSON | API |
| GitHub Security Advisories | API |
| cPanel release notes + security news | RSS |
| LiteSpeed blog | RSS |
| AlmaLinux 8/9 errata | RSS |
| CloudLinux blog + status | RSS |
| Ubuntu USN | RSS |
| seclists oss-sec (keyword-filtered) | RSS |

HTML-only pages (DirectAdmin changelog, Apache vuln HTML, Exim lurker,
OpenSSL secadv HTML, Patchstack, WPScan, etc.) are **not** scraped in v1 —
those products are still covered via NVD / GHSA / Wordfence. Drop in a feed
URL when a vendor publishes one.

## Add a new source (no existing code changes)

If the source is RSS/Atom, append to `config/config.yaml`:

```yaml
  - name: my_vendor_sec
    type: feed
    enabled: true
    url: https://vendor.example/security/feed.xml
    default_products: [myvendor]
    include_keywords: [security, cve, vulnerab]
```

For a new API, add a collector module under `sentinelwatch/collectors/`,
implement `collect() -> list[Vulnerability]`, and register it in
`collectors/__init__.py` (`_build_one`). Then reference `type: your_type` in YAML.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Layout

```
sentinelwatch/
  collectors/     # one module per API type + generic feed
  classifier.py
  db.py
  models.py
  notifier.py
  pipeline.py
config/config.yaml
systemd/
tests/
```

## Out of scope (v1)

- Web dashboard
- Dedicated HTML scrapers for vendors without feeds
- Auto-escalation when a source fails repeatedly
- Live AWX inventory sync for fleet_match (static list for now)

## License

MIT
