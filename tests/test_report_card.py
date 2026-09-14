"""Visual report card generation."""

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
            "before dismissing."
        ),
        channel="critical",
        thread_key="CVE-2024-4577",
    )


def test_telegram_jpeg_readable() -> None:
    data = render_alert_card(_sample())
    assert data is not None
    assert data[:3] == b"\xff\xd8\xff"
    img = Image.open(io.BytesIO(data))
    assert img.size == (1920, 1080)
    # Not a near-black ghost: mean luminance should be clearly above void
    pixels = list(img.getdata())
    mean = sum(sum(p) for p in pixels) / (len(pixels) * 3)
    assert mean > 25, f"image too dark (mean={mean:.1f})"


def test_png_master() -> None:
    png = render_alert_card_png(_sample())
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert Image.open(io.BytesIO(png)).size == (3840, 2160)


def test_html_has_cve() -> None:
    assert "CVE-2024-4577" in build_alert_html(_sample())
    assert "Threat Density" not in build_alert_html(_sample())


def test_digest() -> None:
    assert render_digest_card([_sample()])[:3] == b"\xff\xd8\xff"


def test_write_sources(tmp_path: Path) -> None:
    paths = write_alert_sources(_sample(), tmp_path)
    assert paths["jpg"].stat().st_size > 30_000


def test_caption() -> None:
    assert score_emoji(96) == "☠️"
    assert "CISA KEV" in format_alert_caption(_sample())
