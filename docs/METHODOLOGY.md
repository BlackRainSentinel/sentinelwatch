# Methodology — how SentinelWatch decides what to alert

This is the public scoring / recall contract. Changing it requires a version bump
and a note here — trust comes from predictability.

## Goals

1. **Recall:** never miss a disclosure that matters for the hosting / control-panel
   ecosystem (panels, web servers, mail, DB, DNS, FTP, security stack, PHP, WP core,
   base OS crypto/libs).
2. **Precision:** keep Telegram usable — WordPress plugin noise and non-applicable
   versions must not drown Exim/cPanel/Imunify signal.

## Source tiers

| Tier | Meaning | Examples |
|------|---------|----------|
| 1 | Official vendor / government | CISA KEV, NVD CPE, vendor advisories |
| 2 | High-credibility research | oss-security, scoped GHSA |
| 3 | Aggregators | Wordfence Intelligence v3 |

Tiers are **labels on alerts**, not filters. Tier 3 is still stored.

## Golden recall rule (not tunable by noise reduction)

Immediate alert if **any** of:

- CVE is in **CISA KEV**, or
- CVE is in curated **hosting KEV** (`config/hosting_kev.yaml`), or
- Finding is from a **Tier 1** source that names a tracked taxonomy product
  **and** is version-applicable (or version unknown)

## Version applicability

`config/fleet_versions.yaml` lists versions you run per `vendor:product`.

- No entry for a product → fail **open** (still eligible to alert)
- Finding has no version hints → fail **open**
- Finding versions do not overlap fleet → `version_applicable=false`
  (digest-only unless KEV / hosting-KEV)

## Alert score (0–100)

Approximate weights:

- KEV / hosting-KEV: +40
- CVSS × 3 (cap 30)
- Source tier: T1 +12 / T2 +8 / T3 +3
- Product criticality on shared hosts (panel/mail/security/php weighted higher)
- Blast radius bonus (Imunify/CSF/cPanel/Exim = critical)
- Non-applicable versions: ×0.35 (except KEV)
- Low/medium Wordfence WP plugin noise: ×0.5

Immediate Telegram when: golden rule **or** `channel=critical` **or**
score ≥ `delivery.immediate_min_score` (default 55) with product match.

## Channels

| Channel | Contents |
|---------|----------|
| `critical` | KEV, always-alert, high score, panel/mail/security impact |
| `wordpress` | Tier-3 WP plugin/theme noise (batched digest) |
| `digest` | Everything else |

Optional separate Telegram chat IDs: `TELEGRAM_CHAT_ID_CRITICAL`,
`TELEGRAM_CHAT_ID_WORDPRESS`.

## Reliability contract

- Per-collector isolation (one failure never aborts the run)
- HTTP retries with jitter on 429/5xx
- Consecutive **failures** → Telegram + email
- Consecutive **empty successes** → Telegram (detects dead APIs)
- Heartbeat written every run; stale heartbeat → Telegram
- Daily SQLite `.bak-YYYYMMDD` copy beside the DB
- If Telegram send fails on a critical alert, email is attempted

## Schedules

- **fast** (`--schedule fast`): Tier 1/2, every 2 hours
- **slow** (`--schedule slow`): Tier 3 Wordfence, every 12 hours
- **all**: everything (compat / digest hours)

## Bot commands

`python -m sentinelwatch.bot` (optional systemd unit):

- `/status` — heartbeat + collector health
- `/mute <product_id|wordpress>` — 30-day mute
- `/watch <product_id>` — unmute
- `/why CVE-…` — explain a stored finding
