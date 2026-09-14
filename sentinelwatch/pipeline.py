"""One-shot run with health, scoring, channels, heartbeat (v3)."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelwatch.classifier import (
    build_taxonomy_from_config,
    classify,
)
from sentinelwatch.collectors import build_collectors
from sentinelwatch.collectors.kev import KevCollector
from sentinelwatch.db import Database
from sentinelwatch.hosting_kev import load_hosting_kev
from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import EmailNotifier, TelegramNotifier
from sentinelwatch.scoring import wants_email, wants_immediate_telegram
from sentinelwatch.versions import load_fleet_versions

log = logging.getLogger(__name__)


def run(config: dict[str, Any], *, schedule: str | None = None) -> dict[str, int]:
    root = Path(__file__).resolve().parent.parent
    db_path = Path(config.get("database", {}).get("path", "data/sentinelwatch.db"))
    if not db_path.is_absolute():
        db_path = root / db_path
    db = Database(db_path)
    db.backup()

    taxonomy = build_taxonomy_from_config(config)
    delivery = config.get("delivery") or {}
    email_threshold = float(delivery.get("email_cvss_threshold", 9.0))
    digest_hour = int(delivery.get("digest_hour_utc", 4))
    notify_failures = bool(delivery.get("notify_collector_failures", True))
    empty_streak_alert = int(delivery.get("empty_success_streak_alert", 3))
    fail_streak_alert = int(delivery.get("fail_streak_alert", 2))
    min_score = float(delivery.get("immediate_min_score", 55))
    heartbeat_max_hours = float(delivery.get("heartbeat_max_hours", 14))

    fleet_path = config.get("fleet_versions_path") or "config/fleet_versions.yaml"
    hosting_kev_path = config.get("hosting_kev_path") or "config/hosting_kev.yaml"
    fp = Path(fleet_path)
    hp = Path(hosting_kev_path)
    if not fp.is_absolute():
        fp = root / fp
    if not hp.is_absolute():
        hp = root / hp

    fleet_versions = load_fleet_versions(fp)
    hosting_kev = load_hosting_kev(hp)

    telegram = TelegramNotifier()
    email = EmailNotifier()

    # Dead-man: previous run too old
    age = db.last_heartbeat_age_hours()
    if age is not None and age > heartbeat_max_hours:
        telegram.send_health(
            f"🫀 <b>Heartbeat stale</b>\n"
            f"Last successful pipeline finish was {age:.1f}h ago "
            f"(threshold {heartbeat_max_hours}h). Check systemd timer."
        )

    collectors = build_collectors(config, schedule=schedule)
    stats = {
        "collectors": len(collectors),
        "fetched": 0,
        "new": 0,
        "telegram": 0,
        "email": 0,
        "digest": 0,
        "wp_digest": 0,
        "failures": 0,
        "schedule": schedule or "all",
    }

    kev_cves = db.load_kev_cves()
    fresh: list[Vulnerability] = []

    for collector in collectors:
        try:
            items = collector.collect()
            log.info("%s: fetched %d item(s)", collector.name, len(items))
            stats["fetched"] += len(items)
            health = db.record_collector_success(collector.name, len(items))
            if (
                health["consecutive_empty"] >= empty_streak_alert
                and notify_failures
            ):
                telegram.send_health(
                    f"📭 <b>Empty success streak</b>\n"
                    f"source: <code>{collector.name}</code>\n"
                    f"{health['consecutive_empty']} consecutive runs returned 0 items. "
                    f"API may have changed (Wordfence-v2 class failure)."
                )

            if isinstance(collector, KevCollector) and collector.last_catalog:
                kev_cves = db.upsert_kev_cves(collector.last_catalog)

        except Exception as exc:
            stats["failures"] += 1
            log.exception("Collector %s failed", collector.name)
            fails = db.record_collector_failure(
                collector.name, f"{type(exc).__name__}: {exc}"
            )
            if notify_failures and fails >= fail_streak_alert:
                tb = traceback.format_exc(limit=4)
                telegram.send_failure(
                    collector.name,
                    f"{type(exc).__name__}: {exc}\n\nstreak={fails}\n\n{tb}",
                )
            # Dual path: also email on repeated failures
            if fails >= fail_streak_alert and email.enabled:
                email.send(
                    f"[SentinelWatch] collector failure: {collector.name}",
                    f"streak={fails}\n{exc}\n",
                )
            continue

        for raw in items:
            if not raw.source_tier:
                raw.source_tier = getattr(collector, "source_tier", 3)
            classified = classify(
                raw,
                taxonomy=taxonomy,
                kev_cves=kev_cves,
                hosting_kev=hosting_kev,
                fleet_versions=fleet_versions,
            )
            # Mute support: product id or source
            muted = False
            for key in [classified.source, *classified.matched_products, "wordpress"]:
                if classified.category == "wordpress" and db.is_muted("wordpress"):
                    muted = True
                    break
                if db.is_muted(key):
                    muted = True
                    break
            if muted:
                classified.channel = "digest"
                classified.always_alert = False

            if db.insert_new(classified):
                stats["new"] += 1
                fresh.append(classified)

    for vuln in fresh:
        if wants_immediate_telegram(vuln, min_score=min_score):
            ok = telegram.send_alert(vuln)
            if not ok and email.enabled:
                # Dual notify fallback
                email.send_alert(vuln)
            if ok:
                db.mark_telegram_sent(vuln.dedup_key)
                stats["telegram"] += 1
        if wants_email(vuln, email_threshold):
            if email.send_alert(vuln):
                db.mark_email_sent(vuln.dedup_key)
                stats["email"] += 1

    now = datetime.now(timezone.utc)
    if now.hour == digest_hour and not db.digest_already_sent(now.date()):
        # Main digest (non-wordpress)
        pending = [
            v
            for v in db.pending_digest_items()
            if v.channel != "wordpress"
        ]
        if pending and telegram.send_digest(pending, channel="digest"):
            db.mark_in_digest([v.dedup_key for v in pending])
            stats["digest"] = len(pending)

        wp_pending = db.pending_digest_items(channel="wordpress")
        if wp_pending and telegram.send_digest(
            wp_pending, channel="wordpress", title="WordPress digest"
        ):
            db.mark_in_digest([v.dedup_key for v in wp_pending])
            stats["wp_digest"] = len(wp_pending)

        db.record_digest_sent(now.date())
        log.info(
            "Digests sent digest=%d wp=%d",
            stats["digest"],
            stats["wp_digest"],
        )

    db.heartbeat(stats)
    log.info(
        "Run complete schedule=%s fetched=%d new=%d tg=%d email=%d "
        "digest=%d wp=%d failures=%d",
        stats["schedule"],
        stats["fetched"],
        stats["new"],
        stats["telegram"],
        stats["email"],
        stats["digest"],
        stats["wp_digest"],
        stats["failures"],
    )
    return stats
