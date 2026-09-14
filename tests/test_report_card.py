"""Visual report card generation."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelwatch.models import Vulnerability
from sentinelwatch.report_card import render_alert_card, render_digest_card


def _sample() -> Vulnerability:
    return Vulnerability(
        external_id="CVE-2024-4577",
        source="cisa_kev",
        title="PHP CGI Argument Injection — remote code execution on shared hosts",
        description="Actively exploited CGI argument injection.",
        cvss_score=9.8,
        reported_severity="CRITICAL",
        affected_products=["php:php"],
        cve_ids=["CVE-2024-4577"],
        published_date=datetime(2024, 6, 12, tzinfo=timezone.utc),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
        source_tier=1,
        category="php",
        severity_tier="critical",
        product_match=True,
        matched_products=["php:php"],
        in_kev=True,
        always_alert=True,
        alert_score=96,
        blast_radius="critical",
        impact_note=(
            "PHP-FPM pools serve many tenants. Map to ea-php*/alt-php* "
            "before dismissing; CageFS does not fix interpreter bugs."
        ),
        channel="critical",
        thread_key="CVE-2024-4577",
    )


def test_alert_card_png_bytes() -> None:
    png = render_alert_card(_sample())
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(png) > 5000


def test_digest_card_png_bytes() -> None:
    png = render_digest_card([_sample(), _sample()], title="daily digest")
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
