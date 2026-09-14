"""DB v3: health, heartbeat, mutes, scoring fields."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from sentinelwatch.db import Database
from sentinelwatch.models import Vulnerability


def _vuln(**kwargs) -> Vulnerability:
    defaults = dict(
        external_id="CVE-2024-1",
        source="nvd",
        title="Test",
        description="d",
        cvss_score=9.1,
        reported_severity="CRITICAL",
        affected_products=["php:php"],
        cve_ids=["CVE-2024-1"],
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        url="https://example.test",
        source_tier=1,
        product_match=True,
        matched_products=["php:php"],
        alert_score=80,
        channel="critical",
        thread_key="CVE-2024-1",
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "t.db")


def test_dedup_and_score_fields(db: Database) -> None:
    v = _vuln(in_kev=True, always_alert=True)
    assert db.insert_new(v)
    assert not db.insert_new(v)
    items = db.pending_digest_items()
    assert items[0].alert_score == 80
    assert items[0].thread_key == "CVE-2024-1"


def test_health_and_empty_streak(db: Database) -> None:
    h = db.record_collector_success("wordfence", 0)
    assert h["consecutive_empty"] == 1
    h = db.record_collector_success("wordfence", 0)
    assert h["consecutive_empty"] == 2
    h = db.record_collector_success("wordfence", 5)
    assert h["consecutive_empty"] == 0
    fails = db.record_collector_failure("wordfence", "boom")
    assert fails == 1
    fails = db.record_collector_failure("wordfence", "boom")
    assert fails == 2


def test_heartbeat_and_mute(db: Database) -> None:
    db.heartbeat({"new": 1})
    assert db.last_heartbeat_age_hours() is not None
    assert db.last_heartbeat_age_hours() < 1
    db.set_mute("wordpress", None, "test")
    assert db.is_muted("wordpress")
    db.clear_mute("wordpress")
    assert not db.is_muted("wordpress")


def test_kev_index(db: Database) -> None:
    s = db.upsert_kev_cves(
        [{"cve_id": "cve-2024-9", "vendor": "php", "product": "php", "date_added": "2024-01-01"}]
    )
    assert "CVE-2024-9" in s


def test_digest_channel_filter(db: Database) -> None:
    db.insert_new(_vuln(external_id="A", channel="digest", alert_score=10))
    db.insert_new(_vuln(external_id="B", channel="wordpress", alert_score=10))
    assert {v.external_id for v in db.pending_digest_items("wordpress")} == {"B"}
