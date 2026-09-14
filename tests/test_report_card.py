"""Visual report card generation (HTML → 4K PNG)."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import format_alert_caption
from sentinelwatch.report_card import (
    build_alert_html,
    render_alert_card,
    render_alert_card_png,
    render_digest_card,
    score_emoji,
    score_tier,
    write_alert_sources,
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
        version_applicable=True,
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


def test_alert_html_contains_authoritative_fields() -> None:
    html = build_alert_html(_sample())
    assert "CVE-2024-4577" in html
    assert "php:php" in html
    assert "PHP-CGI Argument Injection" in html
    assert "96" in html
    assert "9.8" in html
    assert "Threat Density" not in html
    assert "LIVE" not in html


def test_master_png_is_4k() -> None:
    png = render_alert_card_png(_sample())
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    img = Image.open(io.BytesIO(png))
    assert img.size == (3840, 2160)


def test_telegram_jpeg_is_1080p() -> None:
    data = render_alert_card(_sample())
    assert data is not None
    assert data[:3] == b"\xff\xd8\xff"
    img = Image.open(io.BytesIO(data))
    assert img.size == (1920, 1080)


def test_digest_card_jpeg() -> None:
    data = render_digest_card([_sample()], title="daily digest")
    assert data is not None
    assert data[:3] == b"\xff\xd8\xff"


def test_write_sources(tmp_path: Path) -> None:
    paths = write_alert_sources(_sample(), tmp_path)
    assert paths["html"].is_file()
    assert paths["png"].is_file()
    assert paths["png"].stat().st_size > 20_000


def test_score_tiers_and_caption() -> None:
    assert score_tier(96) == "catastrophic"
    assert score_emoji(96) == "☠️"
    cap = format_alert_caption(_sample())
    assert "CISA KEV" in cap
