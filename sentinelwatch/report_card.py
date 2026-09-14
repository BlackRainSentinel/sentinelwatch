"""
Telegram threat briefing cards — Pillow only (reliable, high-contrast).

Chrome HTML export remains available for optional 4K docs, but alerts
never depend on it: Telegram gets a crisp 1920×1080 JPEG every time.
"""

from __future__ import annotations

import io
import logging
import math
import re
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

# Telegram-native size — sharp in chat, survives JPEG recompression
W, H = 1920, 1080

# High-contrast ops palette (lighter panels = readable after Telegram crush)
BG = (12, 18, 30)
PANEL = (28, 40, 58)
CARD = (36, 52, 74)
CARD2 = (44, 62, 88)
INK = (255, 255, 255)
MUTED = (168, 184, 204)
TEAL = (20, 220, 200)
TEAL_DIM = (12, 140, 128)
CRIMSON = (255, 64, 78)
AMBER = (255, 196, 48)
GREEN = (72, 220, 150)
LINE = (58, 78, 104)

_SEVERITY = {
    "critical": (CRIMSON, "Critical"),
    "high": (AMBER, "High"),
    "medium": ((90, 170, 255), "Medium"),
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


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates: list[str] = []
    if bold:
        candidates += [
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
        ]
    candidates += [
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
    ]
    for path in candidates:
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def _mono(size: int, bold: bool = False) -> ImageFont.ImageFont:
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ):
        if path and Path(path).is_file():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return _font(size, bold=bold)


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines: list[str] = []
    cur = words[0]
    for w in words[1:]:
        trial = f"{cur} {w}"
        if draw.textlength(trial, font=font) <= max_width:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    lines.append(cur)
    return lines


def _split_title(title: str) -> tuple[str, str]:
    raw = re.sub(r"\s+", " ", (title or "").strip())
    raw = raw.replace("\uFFFD", "").replace("", "—")

    def norm(s: str) -> str:
        return s.replace("PHP CGI", "PHP-CGI")

    if " — " in raw:
        a, b = raw.split(" — ", 1)
        return norm(a.strip()), b.strip()
    if " - " in raw:
        a, b = raw.split(" - ", 1)
        return norm(a.strip()), b.strip()
    return norm(raw) or "Untitled finding", ""


def _fmt_cvss(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def _rounded(draw, xy, r, fill, outline=None, width: int = 2) -> None:
    draw.rounded_rectangle(xy, radius=r, fill=fill, outline=outline, width=width)


def _compact_ring(draw, cx: int, cy: int, r: int, score: float, color) -> None:
    bbox = [cx - r, cy - r, cx + r, cy + r]
    span = 360 * max(0.0, min(100.0, score)) / 100.0
    draw.ellipse(bbox, outline=LINE, width=14)
    # Pillow arc is degrees; draw filled arc as thick arc
    draw.arc(bbox, start=-90, end=-90 + span, fill=color, width=14)


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """High-contrast 1920×1080 JPEG for Telegram sendPhoto."""
    if Image is None:
        return None

    score = float(vuln.alert_score or 0)
    sev_key = (vuln.severity_tier or "unknown").lower()
    sev_color, sev_label = _SEVERITY.get(sev_key, _SEVERITY["unknown"])
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Confirm exposure on your shared-hosting stack."

    stack = ", ".join(vuln.matched_products[:3]) if vuln.matched_products else "Unmatched"
    cve = ", ".join(vuln.cve_ids[:3]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    fleet = "Matches your fleet" if vuln.version_applicable else "Not in fleet versions"
    fleet_color = GREEN if vuln.version_applicable else AMBER
    impact = (vuln.impact_note or "No hosting-specific impact note is available.").strip()

    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # Soft wash (no fine grid — Telegram mud)
    for y in range(H):
        t = y / H
        draw.line(
            [(0, y), (W, y)],
            fill=(
                int(BG[0] + 6 * t),
                int(BG[1] + 8 * t),
                int(BG[2] + 10 * t),
            ),
        )

    # Severity rail
    draw.rectangle([0, 0, 14, H], fill=sev_color)

    # Outer panel
    _rounded(draw, [28, 22, W - 28, H - 22], 20, PANEL, outline=LINE, width=2)

    # ── Header ────────────────────────────────────────────────────
    brand = _font(34, bold=True)
    sub = _font(22)
    draw.text((56, 44), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((56, 86), "Hosting Threat Briefing", font=sub, fill=MUTED)

    pill_f = _font(20, bold=True)
    bx = W - 56
    pills: list[tuple[str, tuple]] = [(sev_label, sev_color)]
    if vuln.in_kev:
        pills.insert(0, ("CISA KEV · exploited", CRIMSON))
    elif vuln.in_hosting_kev:
        pills.insert(0, ("Hosting KEV", AMBER))
    for label, color in pills:
        tw = int(draw.textlength(label, font=pill_f))
        pw = tw + 40
        bx -= pw + 14
        _rounded(draw, [bx, 48, bx + pw, 96], 14, color)
        draw.text((bx + 20, 60), label, font=pill_f, fill=(16, 12, 14))

    draw.line([(56, 120), (W - 56, 120)], fill=LINE, width=2)

    # ── Left severity column (fills height) ───────────────────────
    left_bottom = H - 56
    left = [56, 140, 430, left_bottom]
    _rounded(draw, left, 18, CARD, outline=LINE, width=2)

    draw.text((80, 164), "SENTINEL SCORE", font=_font(20, bold=True), fill=MUTED)

    _compact_ring(draw, 175, 310, 88, score, sev_color)
    sn = _font(86, bold=True)
    st = f"{score:.0f}"
    sw = draw.textlength(st, font=sn)
    draw.text((175 - sw / 2, 262), st, font=sn, fill=INK)
    draw.text((275, 280), "/ 100", font=_font(30, bold=True), fill=MUTED)
    draw.text((275, 330), sev_label, font=_font(30, bold=True), fill=sev_color)

    # Extra left facts from real fields only
    blast = (vuln.blast_radius or "normal").replace("_", " ")
    draw.text((80, 430), "BLAST RADIUS", font=_font(16, bold=True), fill=MUTED)
    draw.text((80, 458), blast.upper(), font=_font(28, bold=True), fill=sev_color)
    draw.text((80, 520), "SOURCE TIER", font=_font(16, bold=True), fill=MUTED)
    tier_plain = {1: "Official", 2: "Research", 3: "Aggregator"}.get(
        int(vuln.source_tier or 3), f"T{vuln.source_tier}"
    )
    draw.text((80, 548), tier_plain, font=_font(28, bold=True), fill=TEAL)

    _rounded(draw, [80, 620, 406, left_bottom - 24], 14, CARD2, outline=LINE, width=2)
    draw.text((104, 644), "CVSS (NVD / vendor)", font=_font(18, bold=True), fill=MUTED)
    draw.text((104, 684), _fmt_cvss(vuln), font=_font(64, bold=True), fill=INK)
    for i, line in enumerate(
        _wrap(draw, "Industry score — separate from Sentinel score", _font(18), 280)[:2]
    ):
        draw.text((104, 770 + i * 28), line, font=_font(18), fill=MUTED)

    # ── Main column ───────────────────────────────────────────────
    mx = 460
    draw.text((mx, 148), headline, font=_font(52, bold=True), fill=INK)
    draw.text((mx, 220), summary, font=_font(28), fill=MUTED)

    facts = [
        ("AFFECTED STACK", stack, TEAL, True),
        ("CVE / ADVISORY", cve, AMBER, True),
        ("CVSS", _fmt_cvss(vuln), INK, False),
        ("FLEET MATCH", fleet, fleet_color, False),
    ]
    fy = 280
    gap = 18
    fw = (W - 56 - mx - 3 * gap) // 4
    fh = 150
    for i, (lab, val, color, mono) in enumerate(facts):
        x = mx + i * (fw + gap)
        _rounded(draw, [x, fy, x + fw, fy + fh], 14, CARD, outline=LINE, width=2)
        draw.rectangle([x, fy, x + 10, fy + fh], fill=color)
        draw.text((x + 24, fy + 22), lab, font=_font(16, bold=True), fill=MUTED)
        vf = _mono(24, bold=True) if mono else _font(24, bold=True)
        for j, line in enumerate(_wrap(draw, val, vf, fw - 44)[:2]):
            draw.text((x + 24, fy + 64 + j * 32), line, font=vf, fill=color)

    # Impact fills remaining vertical space
    iy = fy + fh + 28
    impact_bottom = left_bottom
    _rounded(draw, [mx, iy, W - 56, impact_bottom], 16, CARD, outline=LINE, width=2)
    draw.rectangle([mx, iy, mx + 12, impact_bottom], fill=TEAL)
    draw.text((mx + 36, iy + 28), "OPERATOR IMPACT", font=_font(20, bold=True), fill=TEAL)
    body = _font(28)
    max_lines = max(3, (impact_bottom - iy - 90) // 40)
    for j, line in enumerate(_wrap(draw, impact, body, W - mx - 120)[:max_lines]):
        draw.text((mx + 36, iy + 78 + j * 40), line, font=body, fill=INK)

    # Footer
    foot = _font(17)
    draw.line([(56, H - 48), (W - 56, H - 48)], fill=LINE, width=2)
    source = (vuln.source or "unknown").strip()
    tier = {1: "official", 2: "research", 3: "aggregator"}.get(int(vuln.source_tier or 3), "?")
    left_f = f"Source: {source} ({tier})"
    if vuln.url:
        left_f += f"  ·  {vuln.url}"
    if len(left_f) > 95:
        left_f = left_f[:92] + "…"
    draw.text((56, H - 36), left_f, font=foot, fill=MUTED)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tw = draw.textlength(ts, font=foot)
    draw.text(((W - tw) / 2, H - 36), ts, font=foot, fill=MUTED)
    brand_w = draw.textlength("BLACKRAINSENTINEL", font=foot)
    draw.text((W - 56 - brand_w, H - 36), "BLACKRAINSENTINEL", font=foot, fill=TEAL_DIM)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95, optimize=True, progressive=True, subsampling=0)
    return buf.getvalue()


def render_alert_card_png(vuln: Vulnerability) -> bytes | None:
    """PNG master for docs — same layout, lossless."""
    jpeg = render_alert_card(vuln)
    if not jpeg or Image is None:
        return None
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    # Upscale with LANCZOS for a 4K archive copy (source is vector-like Pillow draw)
    big = img.resize((3840, 2160), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    big.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def build_alert_html(vuln: Vulnerability) -> str:
    """Editable HTML source (optional; Telegram does not use this)."""
    try:
        tmpl = (resources.files("sentinelwatch.briefing") / "alert_card.html").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, TypeError, OSError):
        return "<html><body>briefing template missing</body></html>"

    score = float(vuln.alert_score or 0)
    sev_key = (vuln.severity_tier or "unknown").lower()
    sev_color_hex = {
        "critical": "#e83948",
        "high": "#f0b429",
        "medium": "#5aa8ff",
        "low": "#3dca8e",
        "unknown": "#8b9bb0",
    }.get(sev_key, "#8b9bb0")
    _, sev_label = _SEVERITY.get(sev_key, _SEVERITY["unknown"])
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Confirm exposure on your shared-hosting stack."
    stack = ", ".join(vuln.matched_products[:4]) if vuln.matched_products else "Unmatched"
    cve = ", ".join(vuln.cve_ids[:4]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    fleet = "Matches your fleet" if vuln.version_applicable else "Not in fleet versions"
    fleet_class = "ok" if vuln.version_applicable else "warn"
    impact = (vuln.impact_note or "No hosting-specific impact note is available.").strip()
    source = (vuln.source or "unknown").strip()
    tier = {1: "official source", 2: "research source", 3: "aggregator"}.get(
        int(vuln.source_tier or 3), "source"
    )
    footer = f"Source: {source} ({tier})"
    if vuln.url:
        footer += f" · {vuln.url}"
    c = 2 * math.pi * 48
    dash = f"{c * score / 100:.2f} {c:.2f}"
    pills = ""
    if vuln.in_kev:
        pills += '<span class="pill pill-kev">CISA KEV · actively exploited</span>\n'
    pills += f'<span class="pill pill-sev" data-sev="{escape(sev_key)}">{escape(sev_label)}</span>'

    repl = {
        "{{SEV_COLOR}}": sev_color_hex,
        "{{SEV_KEY}}": escape(sev_key),
        "{{SEV_LABEL}}": escape(sev_label),
        "{{SCORE}}": f"{score:.0f}",
        "{{SCORE_DASH}}": dash,
        "{{CVSS}}": escape(_fmt_cvss(vuln)),
        "{{HEADLINE}}": escape(headline),
        "{{SUMMARY}}": escape(summary),
        "{{STACK}}": escape(stack),
        "{{CVE}}": escape(cve),
        "{{FLEET}}": escape(fleet),
        "{{FLEET_CLASS}}": fleet_class,
        "{{IMPACT}}": escape(impact),
        "{{FOOTER_LEFT}}": escape(footer),
        "{{TIMESTAMP}}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "{{STATUS_PILLS}}": pills,
    }
    for k, v in repl.items():
        tmpl = tmpl.replace(k, v)
    return tmpl


def write_alert_sources(vuln: Vulnerability, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "alert_card.html"
    png_path = out / "alert_card-3840x2160.png"
    jpg_path = out / "alert_card-telegram.jpg"
    html_path.write_text(build_alert_html(vuln), encoding="utf-8")
    png = render_alert_card_png(vuln)
    jpg = render_alert_card(vuln)
    if png:
        png_path.write_bytes(png)
    if jpg:
        jpg_path.write_bytes(jpg)
    return {"html": html_path, "png": png_path, "jpg": jpg_path}


def render_digest_card(items: list[Vulnerability], title: str = "Daily Digest") -> bytes | None:
    if Image is None:
        return None
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 14, H], fill=TEAL)
    _rounded(draw, [36, 28, W - 36, H - 28], 22, PANEL, outline=LINE, width=2)
    draw.text((64, 52), "SENTINELWATCH", font=_font(32, bold=True), fill=TEAL)
    draw.text((64, 96), title, font=_font(22), fill=MUTED)
    draw.text((W - 220, 56), f"{len(items)} items", font=_font(28, bold=True), fill=INK)

    y = 150
    for v in items[:7]:
        sev = (v.severity_tier or "unknown").lower()
        color, _ = _SEVERITY.get(sev, _SEVERITY["unknown"])
        _rounded(draw, [64, y, W - 64, y + 96], 14, CARD, outline=LINE, width=2)
        draw.rectangle([64, y, 80, y + 96], fill=color)
        draw.text((100, y + 28), f"{float(v.alert_score or 0):.0f}", font=_font(32, bold=True), fill=color)
        draw.text((190, y + 22), (v.title or "")[:68], font=_font(22), fill=INK)
        draw.text(
            (190, y + 58),
            f"{sev} · CVSS {_fmt_cvss(v)} · T{v.source_tier}",
            font=_font(18),
            fill=MUTED,
        )
        y += 108

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92, optimize=True, subsampling=0)
    return buf.getvalue()
