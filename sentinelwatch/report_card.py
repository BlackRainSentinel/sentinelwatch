"""
Threat briefing cards — HTML/CSS/SVG source rendered to lossless PNG.

Primary path: Chrome headless screenshot at 3840×2160 (2× of 1920×1080).
Telegram path: high-quality downscale to 1920×1080 JPEG for sendPhoto.
"""

from __future__ import annotations

import io
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from html import escape
from importlib import resources
from pathlib import Path

from sentinelwatch.models import Vulnerability

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFont = None  # type: ignore

log = logging.getLogger(__name__)

LOGICAL_W, LOGICAL_H = 1920, 1080
EXPORT_SCALE = 2
EXPORT_W, EXPORT_H = LOGICAL_W * EXPORT_SCALE, LOGICAL_H * EXPORT_SCALE  # 3840×2160
TELEGRAM_W, TELEGRAM_H = 1920, 1080

CRIMSON = "#e83948"
AMBER = "#f0b429"
BLUE = "#5aa8ff"
GREEN = "#3dca8e"
MUTED = "#8b9bb0"

_SEVERITY = {
    "critical": (CRIMSON, "Critical"),
    "high": (AMBER, "High"),
    "medium": (BLUE, "Medium"),
    "low": (GREEN, "Low"),
    "unknown": (MUTED, "Unknown"),
}


def score_tier(score: float) -> str:
    s = float(score or 0)
    if s >= 90:
        return "catastrophic"
    if s >= 75:
        return "severe"
    if s >= 55:
        return "elevated"
    if s >= 35:
        return "moderate"
    return "watch"


def score_emoji(score: float) -> str:
    return {
        "catastrophic": "☠️",
        "severe": "🔥",
        "elevated": "⚠️",
        "moderate": "📡",
        "watch": "🛰️",
    }[score_tier(score)]


def severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🔵",
        "low": "🟢",
        "unknown": "⚪",
    }.get((severity or "unknown").lower(), "⚪")


def blast_emoji(blast: str) -> str:
    return {
        "critical": "💥",
        "elevated": "⚡",
        "normal": "◇",
        "low": "·",
    }.get((blast or "normal").lower(), "◇")


def _chrome_bin() -> str | None:
    for name in (
        os.environ.get("SENTINELWATCH_CHROME", "").strip(),
        "google-chrome",
        "google-chrome-stable",
        "chromium-browser",
        "chromium",
    ):
        if not name:
            continue
        path = shutil.which(name)
        if path:
            return path
    return None


def _template_html() -> str:
    pkg = resources.files("sentinelwatch.briefing")
    return (pkg / "alert_card.html").read_text(encoding="utf-8")


def _split_title(title: str) -> tuple[str, str]:
    """Headline + one-line summary from source title. No invented content."""
    raw = re.sub(r"\s+", " ", (title or "").strip())
    raw = raw.replace("\uFFFD", "").replace("", "—")
    def _norm_head(s: str) -> str:
        # Plain-language product spelling only — not new technical claims
        return s.replace("PHP CGI", "PHP-CGI").replace("Php Cgi", "PHP-CGI")

    if " — " in raw:
        left, right = raw.split(" — ", 1)
        return _norm_head(left.strip()), right.strip()
    if " - " in raw:
        left, right = raw.split(" - ", 1)
        return _norm_head(left.strip()), right.strip()
    if len(raw) > 72:
        return _norm_head(raw[:72].rstrip()) + "…", raw
    return _norm_head(raw) or "Untitled finding", ""


def _fmt_cvss(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def _score_dash(score: float) -> str:
    c = 2 * math.pi * 48
    filled = c * max(0.0, min(100.0, float(score or 0))) / 100.0
    return f"{filled:.2f} {c:.2f}"


def _status_pills(vuln: Vulnerability, sev_key: str, sev_label: str) -> str:
    parts: list[str] = []
    if vuln.in_kev:
        parts.append('<span class="pill pill-kev">CISA KEV · actively exploited</span>')
    if vuln.in_hosting_kev:
        parts.append('<span class="pill pill-hosting">Hosting KEV</span>')
    parts.append(
        f'<span class="pill pill-sev" data-sev="{escape(sev_key)}">{escape(sev_label)}</span>'
    )
    return "\n".join(parts)


def build_alert_html(vuln: Vulnerability) -> str:
    """Fill the editable HTML/CSS/SVG briefing template."""
    score = float(vuln.alert_score or 0)
    sev_key = (vuln.severity_tier or "unknown").lower()
    sev_color, sev_label = _SEVERITY.get(sev_key, _SEVERITY["unknown"])
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Review the advisory and confirm exposure on your shared-hosting stack."

    stack = (
        ", ".join(vuln.matched_products[:4])
        if vuln.matched_products
        else "Unmatched — review manually"
    )
    cve = ", ".join(vuln.cve_ids[:4]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    if vuln.version_applicable:
        fleet, fleet_class = "Matches your fleet", "ok"
    else:
        fleet, fleet_class = "Not in fleet versions", "warn"

    impact = (vuln.impact_note or "").strip()
    if not impact:
        impact = "No hosting-specific impact note is available for this match."

    source = (vuln.source or "unknown").strip()
    tier = int(vuln.source_tier or 3)
    tier_plain = {1: "official source", 2: "research source", 3: "aggregator"}.get(
        tier, f"tier {tier}"
    )
    footer_left = f"Source: {source} ({tier_plain})"
    if vuln.url:
        footer_left += f" · {vuln.url}"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = _template_html()
    replacements = {
        "{{SEV_COLOR}}": sev_color,
        "{{SEV_KEY}}": escape(sev_key),
        "{{SEV_LABEL}}": escape(sev_label),
        "{{SCORE}}": f"{score:.0f}",
        "{{SCORE_DASH}}": _score_dash(score),
        "{{CVSS}}": escape(_fmt_cvss(vuln)),
        "{{HEADLINE}}": escape(headline),
        "{{SUMMARY}}": escape(summary),
        "{{STACK}}": escape(stack),
        "{{CVE}}": escape(cve),
        "{{FLEET}}": escape(fleet),
        "{{FLEET_CLASS}}": fleet_class,
        "{{IMPACT}}": escape(impact),
        "{{FOOTER_LEFT}}": escape(footer_left),
        "{{TIMESTAMP}}": escape(ts),
        "{{STATUS_PILLS}}": _status_pills(vuln, sev_key, sev_label),
    }
    for key, val in replacements.items():
        html = html.replace(key, val)
    return html


def _render_chrome_png(html: str) -> bytes | None:
    chrome = _chrome_bin()
    if not chrome:
        log.warning("Chrome/Chromium not found; cannot render HTML briefing")
        return None

    with tempfile.TemporaryDirectory(prefix="sw-brief-") as tmp:
        tmp_path = Path(tmp)
        html_path = tmp_path / "alert.html"
        png_path = tmp_path / "alert.png"
        html_path.write_text(html, encoding="utf-8")
        uri = html_path.resolve().as_uri()

        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--allow-file-access-from-files",
            "--hide-scrollbars",
            "--force-device-scale-factor=2",
            f"--window-size={LOGICAL_W},{LOGICAL_H}",
            f"--screenshot={png_path}",
            uri,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("Chrome screenshot failed: %s", exc)
            return None

        if not png_path.is_file() or png_path.stat().st_size < 1000:
            log.warning(
                "Chrome screenshot missing/empty (exit=%s): %s",
                proc.returncode,
                (proc.stderr or proc.stdout or "")[:400],
            )
            return None

        data = png_path.read_bytes()
        if Image is None:
            return data

        img = Image.open(io.BytesIO(data))
        if img.mode != "RGB":
            img = img.convert("RGB")
        if img.size != (EXPORT_W, EXPORT_H):
            img = img.resize((EXPORT_W, EXPORT_H), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()


def _pillow_fallback(vuln: Vulnerability) -> bytes | None:
    """Readable Pillow fallback when Chrome is unavailable."""
    if Image is None:
        return None

    score = float(vuln.alert_score or 0)
    sev_key = (vuln.severity_tier or "unknown").lower()
    sev_color_hex, sev_label = _SEVERITY.get(sev_key, _SEVERITY["unknown"])
    sev_rgb = tuple(int(sev_color_hex[i : i + 2], 16) for i in (1, 3, 5))
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Review the advisory and confirm exposure on your shared-hosting stack."

    W, H = EXPORT_W, EXPORT_H
    scale = EXPORT_SCALE
    img = Image.new("RGB", (W, H), (11, 18, 32))
    draw = ImageDraw.Draw(img)

    def font(size: int, bold: bool = False):
        path = (
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"
        )
        alt = (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        )
        for p in (path, alt):
            if Path(p).is_file():
                try:
                    return ImageFont.truetype(p, size * scale)
                except OSError:
                    continue
        return ImageFont.load_default()

    def wrap(text: str, fnt, max_w: int) -> list[str]:
        words = text.split()
        if not words:
            return [""]
        lines: list[str] = []
        cur = words[0]
        for w in words[1:]:
            trial = f"{cur} {w}"
            if draw.textlength(trial, font=fnt) <= max_w:
                cur = trial
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
        return lines

    draw.rectangle([0, 0, 10 * scale, H], fill=sev_rgb)
    pad = 44 * scale
    draw.text((pad, 40 * scale), "SENTINELWATCH", font=font(28, True), fill=(30, 200, 184))
    draw.text((pad, 78 * scale), "Hosting Threat Briefing", font=font(20), fill=(139, 155, 176))

    panel = [pad, 140 * scale, pad + 340 * scale, H - 80 * scale]
    draw.rounded_rectangle(panel, radius=16 * scale, fill=(18, 27, 44), outline=(42, 58, 82), width=2)
    draw.text((pad + 24 * scale, 160 * scale), "SENTINEL SCORE", font=font(18, True), fill=(168, 182, 200))
    draw.text((pad + 24 * scale, 210 * scale), f"{score:.0f}", font=font(72, True), fill=(242, 245, 248))
    draw.text((pad + 24 * scale, 300 * scale), "out of 100", font=font(22, True), fill=(139, 155, 176))
    draw.text((pad + 24 * scale, 340 * scale), sev_label, font=font(20, True), fill=sev_rgb)
    draw.text((pad + 24 * scale, 420 * scale), "CVSS (vendor / NVD)", font=font(16, True), fill=(139, 155, 176))
    draw.text((pad + 24 * scale, 450 * scale), _fmt_cvss(vuln), font=font(40, True), fill=(242, 245, 248))
    draw.text(
        (pad + 24 * scale, 510 * scale),
        "Industry severity — separate from Sentinel score",
        font=font(16),
        fill=(139, 155, 176),
    )

    mx = pad + 380 * scale
    draw.text((mx, 140 * scale), headline, font=font(48, True), fill=(242, 245, 248))
    sy = 220 * scale
    for line in wrap(summary, font(24), W - mx - pad)[:3]:
        draw.text((mx, sy), line, font=font(24), fill=(168, 182, 200))
        sy += 36 * scale

    fy = 340 * scale
    facts = [
        ("AFFECTED STACK", ", ".join(vuln.matched_products[:3]) if vuln.matched_products else "Unmatched"),
        ("CVE / ADVISORY", ", ".join(vuln.cve_ids[:3]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")),
        ("CVSS", _fmt_cvss(vuln)),
        ("FLEET MATCH", "Matches your fleet" if vuln.version_applicable else "Not in fleet versions"),
    ]
    fw = (W - mx - pad - 36 * scale) // 4
    for i, (lab, val) in enumerate(facts):
        x = mx + i * (fw + 12 * scale)
        draw.rounded_rectangle(
            [x, fy, x + fw, fy + 120 * scale],
            radius=12 * scale,
            fill=(24, 35, 53),
            outline=(42, 58, 82),
            width=2,
        )
        draw.text((x + 16 * scale, fy + 16 * scale), lab, font=font(14, True), fill=(139, 155, 176))
        for j, line in enumerate(wrap(val, font(20, True), fw - 32 * scale)[:2]):
            draw.text(
                (x + 16 * scale, fy + 48 * scale + j * 28 * scale),
                line,
                font=font(20, True),
                fill=(242, 245, 248),
            )

    impact = (vuln.impact_note or "No hosting-specific impact note is available for this match.").strip()
    iy = 500 * scale
    draw.rounded_rectangle(
        [mx, iy, W - pad, H - 80 * scale],
        radius=16 * scale,
        fill=(18, 27, 44),
        outline=(42, 58, 82),
        width=2,
    )
    draw.rectangle([mx, iy, mx + 6 * scale, H - 80 * scale], fill=(30, 200, 184))
    draw.text((mx + 28 * scale, iy + 24 * scale), "OPERATOR IMPACT", font=font(18, True), fill=(30, 200, 184))
    ty = iy + 64 * scale
    for line in wrap(impact, font(24), W - mx - pad - 56 * scale)[:5]:
        draw.text((mx + 28 * scale, ty), line, font=font(24), fill=(242, 245, 248))
        ty += 36 * scale

    foot = font(16)
    draw.text((pad, H - 48 * scale), "sentinelwatch · shared-hosting early warning", font=foot, fill=(139, 155, 176))
    draw.text((W - pad - 280 * scale, H - 48 * scale), "BLACKRAINSENTINEL", font=foot, fill=(14, 122, 114))

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def render_alert_card_png(vuln: Vulnerability) -> bytes | None:
    """Lossless 3840×2160 PNG from HTML source (Chrome) or Pillow fallback."""
    html = build_alert_html(vuln)
    png = _render_chrome_png(html)
    if png:
        return png
    return _pillow_fallback(vuln)


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Telegram-ready 1920×1080 JPEG derived from the 4K master."""
    png = render_alert_card_png(vuln)
    if not png or Image is None:
        return png
    img = Image.open(io.BytesIO(png)).convert("RGB")
    if img.size != (TELEGRAM_W, TELEGRAM_H):
        img = img.resize((TELEGRAM_W, TELEGRAM_H), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92, optimize=True, progressive=True)
    return buf.getvalue()


def write_alert_sources(vuln: Vulnerability, out_dir: str | Path) -> dict[str, Path]:
    """Write editable HTML + master PNG for review/delivery."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "alert_card.html"
    png_path = out / "alert_card-3840x2160.png"
    html_path.write_text(build_alert_html(vuln), encoding="utf-8")
    png = render_alert_card_png(vuln)
    if png:
        png_path.write_bytes(png)
    return {"html": html_path, "png": png_path}


def render_digest_card(items: list[Vulnerability], title: str = "Daily Digest") -> bytes | None:
    if Image is None:
        return None
    W, H = TELEGRAM_W, TELEGRAM_H
    img = Image.new("RGB", (W, H), (11, 18, 32))
    draw = ImageDraw.Draw(img)

    def font(size: int, bold: bool = False):
        path = (
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"
        )
        alt = (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        )
        for p in (path, alt):
            if Path(p).is_file():
                try:
                    return ImageFont.truetype(p, size)
                except OSError:
                    continue
        return ImageFont.load_default()

    draw.rectangle([0, 0, 8, H], fill=(30, 200, 184))
    draw.text((40, 36), "SENTINELWATCH", font=font(28, True), fill=(30, 200, 184))
    draw.text((40, 74), title, font=font(20), fill=(139, 155, 176))
    draw.text((W - 200, 40), f"{len(items)} items", font=font(24, True), fill=(242, 245, 248))

    y = 120
    for v in items[:7]:
        sev = (v.severity_tier or "unknown").lower()
        color_hex = _SEVERITY.get(sev, _SEVERITY["unknown"])[0]
        color = tuple(int(color_hex[i : i + 2], 16) for i in (1, 3, 5))
        draw.rounded_rectangle([40, y, W - 40, y + 88], radius=12, fill=(18, 27, 44), outline=(42, 58, 82))
        draw.rectangle([40, y, 52, y + 88], fill=color)
        draw.text((70, y + 22), f"{float(v.alert_score or 0):.0f}", font=font(28, True), fill=color)
        head = (v.title or "")[:70]
        draw.text((150, y + 18), head, font=font(20), fill=(242, 245, 248))
        draw.text(
            (150, y + 52),
            f"{sev} · CVSS {_fmt_cvss(v)} · T{v.source_tier}",
            font=font(16),
            fill=(139, 155, 176),
        )
        y += 100

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90, optimize=True)
    return buf.getvalue()
