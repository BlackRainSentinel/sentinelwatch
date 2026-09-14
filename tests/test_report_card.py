"""Black Rain threat poster tests."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from sentinelwatch.models import Vulnerability
from sentinelwatch.notifier import format_alert_caption
from sentinelwatch.report_card import (
    render_alert_card,
    render_alert_card_png,
    render_digest_card,
    score_emoji,
    write_alert_sources,
)


def _sample() -> Vulnerability:
    return Vulnerability(
        external_id="CVE-2024-4577",
        source="cisa_kev",
        title="PHP CGI Argument Injection — remote code execution on shared hosts",
        description="x",
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
        alert_score=96,
        blast_radius="critical",
        impact_note="PHP-FPM pools serve many tenants. Map ea-php*/alt-php* before dismissing.",
        channel="critical",
        thread_key="CVE-2024-4577",
    )


def test_poster_square() -> None:
    data = render_alert_card(_sample())
    assert data is not None and data[:3] == b"\xff\xd8\xff"
    img = Image.open(io.BytesIO(data))
    assert img.size == (1280, 1280)
    assert sum(img.getpixel((640, 640))) > 20


def test_png_and_digest(tmp_path: Path) -> None:
    assert render_alert_card_png(_sample())[:8] == b"\x89PNG\r\n\x1a\n"
    assert render_digest_card([_sample()])[:3] == b"\xff\xd8\xff"
    assert write_alert_sources(_sample(), tmp_path)["jpg"].stat().st_size > 50_000


def test_caption_structure() -> None:
    cap = format_alert_caption(_sample())
    assert "Scores" in cap
    assert "Why it matters" in cap
    assert "CVE-2024-4577" in cap
    assert "PHP-CGI" in cap
    assert score_emoji(96) == "☠️"
    assert "🧨" not in cap  # less emoji spam
