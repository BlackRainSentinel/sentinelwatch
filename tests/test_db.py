"""Dedup layer: source:external_id is processed once."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinelwatch.db import Database
from sentinelwatch.models import Vulnerability


def _vuln(external_id: str = "CVE-2024-1", source: str = "nvd", **kwargs) -> Vulnerability:
    defaults = dict(
        external_id=external_id,
        source=source,
        title="Test finding",
        description="desc",
        cvss_score=9.1,
        reported_severity="CRITICAL",
        affected_products=["php"],
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        url="https://example.test/cve",
        references=[],
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "test.db")


def test_insert_new_returns_true_once(db: Database) -> None:
    v = _vuln()
    assert db.insert_new(v) is True
    assert db.is_seen(v) is True
    assert db.insert_new(v) is False


def test_same_id_different_source_are_independent(db: Database) -> None:
    a = _vuln(source="nvd", external_id="CVE-2024-9")
    b = _vuln(source="wordfence", external_id="CVE-2024-9", title="WF copy")
    assert db.insert_new(a) is True
    assert db.insert_new(b) is True
    assert a.dedup_key != b.dedup_key


def test_failed_parse_never_marks_seen(db: Database) -> None:
    """Simulate a collector failure: nothing inserted → nothing marked seen."""
    v = _vuln(external_id="CVE-NEVER")
    assert db.is_seen(v) is False


def test_digest_bookkeeping(db: Database) -> None:
    from datetime import date

    day = date(2024, 6, 1)
    assert db.digest_already_sent(day) is False
    db.record_digest_sent(day)
    assert db.digest_already_sent(day) is True


def test_pending_digest_and_mark(db: Database) -> None:
    v1 = _vuln(external_id="A", severity_tier="high")
    v2 = _vuln(external_id="B", severity_tier="low", cvss_score=2.0)
    # severity_tier on Vulnerability is set by classifier normally; set before insert
    v1.severity_tier = "high"
    v2.severity_tier = "low"
    assert db.insert_new(v1)
    assert db.insert_new(v2)

    pending = db.pending_digest_items()
    assert {p.external_id for p in pending} == {"A", "B"}

    db.mark_in_digest([v1.dedup_key])
    pending2 = db.pending_digest_items()
    assert [p.external_id for p in pending2] == ["B"]
