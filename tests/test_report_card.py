"""Visual report card generation."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import format_alert_caption
from sentinelwatch.report_card import (
    render_alert_card,
    render_digest_card,
    score_emoji,
    score_tier,
)


def _sample(*, score: float = 96.0) -> Vulnerability:
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
        alert_score=score,
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
    assert len(png) > 20_000


def test_alert_card_high_resolution() -> None:
    from PIL import Image
    import io

    png = render_alert_card(_sample())
    assert png is not None
    img = Image.open(io.BytesIO(png))
    assert img.size == (2560, 1440)


def test_digest_card_png_bytes() -> None:
    png = render_digest_card([_sample(), _sample()], title="daily digest")
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


def test_score_tiers_and_emoji() -> None:
    assert score_tier(96) == "catastrophic"
    assert score_tier(80) == "severe"
    assert score_tier(60) == "elevated"
    assert score_tier(40) == "moderate"
    assert score_tier(10) == "watch"
    assert score_emoji(96) == "☠️"
    assert score_emoji(40) == "📡"


def test_caption_emoji_scales_with_score() -> None:
    high = format_alert_caption(_sample(score=96))
    low = format_alert_caption(_sample(score=20))
    assert "☠️" in high or "💀" in high
    assert "CISA KEV" in high
    assert "🛰️" in low or "WATCHLIST" in low or "📡" in low
