"""Classifier, scoring, version applicability (v3)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinelwatch.classifier import classify, match_products, severity_tier
from sentinelwatch.models import Vulnerability
from sentinelwatch.scoring import wants_email, wants_immediate_telegram
from sentinelwatch.taxonomy import PRODUCTS
from sentinelwatch.versions import check_applicability, version_in_range



def _v(**kwargs) -> Vulnerability:
    base = dict(
        external_id="X",
        source="test",
        title="Something",
        description="",
        cvss_score=None,
        reported_severity=None,
        affected_products=[],
        cve_ids=[],
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        url="https://example.test",
        source_tier=3,
    )
    base.update(kwargs)
    return Vulnerability(**base)


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.0, "critical"),
        (7.0, "high"),
        (4.0, "medium"),
        (3.9, "low"),
        (None, "unknown"),
    ],
)
def test_severity_tiers(score, expected) -> None:
    assert severity_tier(score) == expected


def test_substring_false_positive_gone() -> None:
    v = _v(title="Typography emphasis rendering bug in theme")
    assert match_products(v, PRODUCTS) == []


def test_php_word_boundary() -> None:
    v = classify(_v(title="PHP remote code execution in FPM"), PRODUCTS)
    assert v.product_match and "php:php" in v.matched_products


def test_cpe_and_version_applicability() -> None:
    v = classify(
        _v(
            title="PHP issue",
            affected_products=["php:php"],
            affected_versions=["<8.0"],
            source_tier=1,
        ),
        PRODUCTS,
        fleet_versions={"php:php": ["8.2"]},
    )
    assert v.product_match
    assert v.version_applicable is False
    assert wants_immediate_telegram(v) is False


def test_version_applicable_overlap() -> None:
    assert version_in_range("8.2", ">=8.1")
    assert version_in_range("8.2", "<8.3")
    assert not version_in_range("8.2", "<8.0")
    ok, unknown = check_applicability(
        ["php:php"], [">=8.1", "<8.3"], {"php:php": ["8.2"]}
    )
    assert ok and not unknown


def test_kev_and_hosting_kev_force_alert() -> None:
    v = classify(
        _v(title="Unrelated", cve_ids=["CVE-2024-4577"], source_tier=3),
        PRODUCTS,
        hosting_kev={"CVE-2024-4577"},
    )
    assert v.in_hosting_kev and v.always_alert
    assert wants_immediate_telegram(v)


def test_imunify_blast_radius_critical() -> None:
    v = classify(
        _v(title="Imunify360 agent vulnerability", source_tier=1),
        PRODUCTS,
    )
    assert v.blast_radius == "critical"
    assert "SECURITY PRODUCT" in v.impact_note.upper() or "Imunify" in v.impact_note


def test_wordpress_goes_to_wp_channel() -> None:
    v = classify(
        _v(
            title="WordPress plugin XSS in contact form",
            source="wordfence",
            source_tier=3,
            cvss_score=5.0,
        ),
        PRODUCTS,
    )
    assert v.channel == "wordpress"
    assert wants_immediate_telegram(v) is False


def test_tier1_exim_scores_high() -> None:
    v = classify(
        _v(title="Exim ACL remote code execution", source_tier=1, cvss_score=9.8),
        PRODUCTS,
    )
    assert v.channel == "critical"
    assert v.alert_score >= 55
    assert wants_immediate_telegram(v)
    assert wants_email(v)


def test_cve_ids_cleaned_from_products() -> None:
    v = classify(
        _v(title="Exim", affected_products=["exim:exim", "CVE-2024-12345"]),
        PRODUCTS,
    )
    assert "CVE-2024-12345" in v.cve_ids
    assert "CVE-2024-12345" not in v.affected_products
