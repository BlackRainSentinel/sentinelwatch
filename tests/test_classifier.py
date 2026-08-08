"""Classifier + delivery rule predicates."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinelwatch.classifier import (
    classify,
    severity_tier,
    wants_email,
    wants_immediate_telegram,
)
from sentinelwatch.models import Vulnerability


def _v(**kwargs) -> Vulnerability:
    base = dict(
        external_id="X",
        source="test",
        title="Something",
        description="",
        cvss_score=None,
        reported_severity=None,
        affected_products=[],
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        url="https://example.test",
    )
    base.update(kwargs)
    return Vulnerability(**base)


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.0, "critical"),
        (9.8, "critical"),
        (7.0, "high"),
        (8.9, "high"),
        (4.0, "medium"),
        (6.9, "medium"),
        (3.9, "low"),
        (0.0, "low"),
        (None, "unknown"),
    ],
)
def test_severity_tiers(score, expected) -> None:
    assert severity_tier(score) == expected


def test_category_panel() -> None:
    v = classify(_v(title="cPanel WHM privilege issue"), [])
    assert v.category == "panel"


def test_category_wordpress() -> None:
    v = classify(
        _v(title="Plugin XSS", affected_products=["wordpress", "contact-form"]),
        [],
    )
    assert v.category == "wordpress"


def test_fleet_match_from_allowlist() -> None:
    v = classify(_v(title="Exim RCE in ACL"), ["exim", "php"])
    assert v.fleet_match is True


def test_fleet_miss() -> None:
    v = classify(_v(title="Unrelated vendor advisory"), ["exim", "php"])
    assert v.fleet_match is False


def test_telegram_critical_immediate() -> None:
    v = classify(_v(title="Apache bug", cvss_score=9.5), [])
    assert v.severity_tier == "critical"
    assert wants_immediate_telegram(v) is True


def test_telegram_unknown_without_fleet_deferred() -> None:
    v = classify(_v(title="RSS noise without score"), [])
    assert v.severity_tier == "unknown"
    assert v.fleet_match is False
    assert wants_immediate_telegram(v) is False


def test_telegram_medium_with_fleet_immediate() -> None:
    v = classify(_v(title="MariaDB medium issue", cvss_score=5.0), ["mariadb"])
    assert v.severity_tier == "medium"
    assert v.fleet_match is True
    assert wants_immediate_telegram(v) is True


def test_email_threshold_and_fleet() -> None:
    high = classify(_v(title="OpenSSL", cvss_score=9.0), [])
    assert wants_email(high, 9.0) is True

    mid = classify(_v(title="OpenSSL", cvss_score=7.5), [])
    assert wants_email(mid, 9.0) is False

    fleet = classify(_v(title="LiteSpeed low", cvss_score=2.0), ["litespeed"])
    assert wants_email(fleet, 9.0) is True
