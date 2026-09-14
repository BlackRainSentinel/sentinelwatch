"""Visual report card — editorial poster."""

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


def test_poster_telegram_size() -> None:
    data = render_alert_card(_sample())
    assert data is not None
    assert data[:3] == b"\xff\xd8\xff"
    img = Image.open(io.BytesIO(data))
    assert img.size[0] == 1080
    assert 900 <= img.size[1] <= 1440
    sample = [img.getpixel((x, y)) for x, y in ((100, 40), (540, 200), (100, 500))]
    assert any(sum(p) > 80 for p in sample)


def test_png_2x() -> None:
    png = render_alert_card_png(_sample())
    assert png is not None
    img = Image.open(io.BytesIO(png))
    assert img.size[0] == 2160
    assert img.size[1] >= 1800


def test_html_banner() -> None:
    html = build_alert_html(_sample())
    assert "CISA KEV" in html
    assert "CVE-2024-4577" in html
    assert "gauge" not in html.lower()


def test_digest_and_sources(tmp_path: Path) -> None:
    assert render_digest_card([_sample()])[:3] == b"\xff\xd8\xff"
    paths = write_alert_sources(_sample(), tmp_path)
    assert paths["jpg"].stat().st_size > 40_000


def test_caption() -> None:
    assert score_emoji(96) == "☠️"
    assert "CISA KEV" in format_alert_caption(_sample())
