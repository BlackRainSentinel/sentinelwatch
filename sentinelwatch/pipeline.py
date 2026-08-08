"""One-shot run: collect → dedup → classify → deliver (+ optional digest)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelwatch.classifier import (
    classify,
    wants_email,
    wants_immediate_telegram,
)
from sentinelwatch.collectors import build_collectors
from sentinelwatch.db import Database
from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import EmailNotifier, TelegramNotifier

log = logging.getLogger(__name__)


def run(config: dict[str, Any]) -> dict[str, int]:
    """
    Execute a full monitoring cycle. Collector failures are isolated —
    one bad source never aborts the run.
    """
    db_path = Path(config.get("database", {}).get("path", "data/sentinelwatch.db"))
    db = Database(db_path)

    fleet = list(config.get("fleet_software") or [])
    delivery = config.get("delivery") or {}
    email_threshold = float(delivery.get("email_cvss_threshold", 9.0))
    digest_hour = int(delivery.get("digest_hour_utc", 4))

    telegram = TelegramNotifier()
    email = EmailNotifier()

    collectors = build_collectors(config)
    stats = {
        "collectors": len(collectors),
        "fetched": 0,
        "new": 0,
        "telegram": 0,
        "email": 0,
        "digest": 0,
        "failures": 0,
    }

    fresh: list[Vulnerability] = []

    for collector in collectors:
        try:
            items = collector.collect()
            log.info("%s: fetched %d item(s)", collector.name, len(items))
            stats["fetched"] += len(items)
        except Exception:
            stats["failures"] += 1
            log.exception("Collector %s failed; will retry next run", collector.name)
            continue

        for raw in items:
            classified = classify(raw, fleet)
            if db.insert_new(classified):
                stats["new"] += 1
                fresh.append(classified)

    for vuln in fresh:
        if wants_immediate_telegram(vuln):
            if telegram.send_alert(vuln):
                db.mark_telegram_sent(vuln.dedup_key)
                stats["telegram"] += 1
        if wants_email(vuln, email_threshold):
            if email.send_alert(vuln):
                db.mark_email_sent(vuln.dedup_key)
                stats["email"] += 1

    now = datetime.now(timezone.utc)
    if now.hour == digest_hour and not db.digest_already_sent(now.date()):
        pending = db.pending_digest_items()
        if pending:
            if telegram.send_digest(pending):
                db.mark_in_digest([v.dedup_key for v in pending])
                db.record_digest_sent(now.date())
                stats["digest"] = len(pending)
                log.info("Daily digest sent (%d items)", len(pending))
        else:
            # Still record the day so we don't keep checking empties every minute
            # (timer only fires twice/day, but be safe).
            db.record_digest_sent(now.date())
            log.info("Digest hour matched; nothing pending")
    elif now.hour == digest_hour:
        log.info("Digest already sent for %s", now.date().isoformat())
    else:
        log.debug(
            "Skipping digest (hour=%d, configured=%d UTC)", now.hour, digest_hour
        )

    log.info(
        "Run complete: fetched=%d new=%d telegram=%d email=%d digest=%d failures=%d",
        stats["fetched"],
        stats["new"],
        stats["telegram"],
        stats["email"],
        stats["digest"],
        stats["failures"],
    )
    return stats
