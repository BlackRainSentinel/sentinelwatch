"""
Telegram-first threat briefing cards.

Designed for sendPhoto (big inline preview in chat), not document
attachments. Flat high-contrast poster layout so Telegram's JPEG
recompression still stays readable.
"""

from __future__ import annotations

import io
import math
from datetime import datetime, timezone
from pathlib import Path

from sentinelwatch.models import Vulnerability

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFont = None  # type: ignore


# Palette — high contrast for Telegram JPEG
INK = (10, 14, 22)
PANEL = (18, 26, 38)
PANEL2 = (26, 38, 54)
TEAL = (0, 230, 210)
AMBER = (255, 190, 45)
CRIMSON = (255, 55, 70)
ICE = (245, 248, 252)
MUTED = (140, 158, 178)
LINE = (48, 68, 90)
GREEN = (70, 220, 150)

_SEVERITY_COLOR = {
    "critical": CRIMSON,
    "high": AMBER,
    "medium": (80, 170, 255),
    "low": GREEN,
    "unknown": MUTED,
}

# Telegram sweet spot: full-width chat photo, not a file thumbnail.
# ~1280px longest edge is what Telegram keeps sharp for sendPhoto.
W, H = 1280, 720


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


def _tier_heat(score: float) -> tuple[int, int, int]:
    return {
        "catastrophic": CRIMSON,
        "severe": (255, 110, 50),
        "elevated": AMBER,
        "moderate": (80, 170, 255),
        "watch": TEAL,
    }[score_tier(score)]


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates: list[str] = []
    if bold:
        candidates += [
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        ]
    candidates += [
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        if Path(path).is_file():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


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


def _rounded(draw: ImageDraw.ImageDraw, xy, radius: int, fill, outline=None, width: int = 1) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def _fmt_cvss(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def _chip(draw, x: int, y: int, label: str, font, fg, bg) -> int:
    tw = int(draw.textlength(label, font=font))
    w = tw + 28
    h = 36
    _rounded(draw, [x, y, x + w, y + h], 10, bg)
    draw.text((x + 14, y + 8), label, font=font, fill=fg)
    return x + w + 10


def _gauge(draw: ImageDraw.ImageDraw, cx: int, cy: int, r: int, score: float, color) -> None:
    bbox = [cx - r, cy - r, cx + r, cy + r]
    span = 270 * max(0.0, min(100.0, score)) / 100.0
    draw.arc(bbox, start=135, end=405, fill=LINE, width=16)
    draw.arc(bbox, start=135, end=135 + span, fill=color, width=16)
    # Inner ring accent
    inner = [cx - r + 28, cy - r + 28, cx + r - 28, cy + r - 28]
    draw.arc(inner, start=135, end=405, fill=PANEL2, width=4)
    draw.ellipse([cx - r + 36, cy - r + 36, cx + r - 36, cy + r - 36], fill=PANEL)

    # ticks
    for i in range(0, 11):
        ang = math.radians(135 + 27 * i)
        x0 = cx + (r - 22) * math.cos(ang)
        y0 = cy + (r - 22) * math.sin(ang)
        x1 = cx + (r - 10) * math.cos(ang)
        y1 = cy + (r - 10) * math.sin(ang)
        draw.line([(x0, y0), (x1, y1)], fill=color if i <= score / 10 else MUTED, width=3)


def _encode_photo(img: Image.Image) -> bytes:
    """JPEG for Telegram sendPhoto — native path, full-size chat preview."""
    buf = io.BytesIO()
    # RGB JPEG; high quality so text survives Telegram's second pass
    img.save(buf, format="JPEG", quality=95, optimize=True, progressive=True)
    return buf.getvalue()


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Return JPEG bytes for Telegram sendPhoto, or None if Pillow missing."""
    if Image is None:
        return None

    score = float(vuln.alert_score or 0)
    heat = _tier_heat(score)
    sev = (vuln.severity_tier or "unknown").lower()
    sev_color = _SEVERITY_COLOR.get(sev, MUTED)
    tier = score_tier(score)

    img = Image.new("RGB", (W, H), INK)
    draw = ImageDraw.Draw(img)

    # Soft vertical wash (no fine grid — grids turn to mud after Telegram JPEG)
    for y in range(H):
        t = y / H
        r = int(INK[0] + 8 * t)
        g = int(INK[1] + 10 * t)
        b = int(INK[2] + 14 * t)
        # heat tint top
        r = min(255, int(r + heat[0] * 0.04 * (1 - t)))
        draw.line([(0, y), (W, y)], fill=(r, g, b))

    # Severity rail
    draw.rectangle([0, 0, 12, H], fill=sev_color)

    # Main panel
    _rounded(draw, [28, 24, W - 28, H - 24], 20, PANEL)

    # Header
    brand = _font(28, bold=True)
    sub = _font(14)
    draw.text((52, 42), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((52, 76), "HOSTING THREAT BRIEFING", font=sub, fill=MUTED)
    draw.rectangle([52, 98, 280, 102], fill=TEAL)

    # Live + badges
    draw.ellipse([W - 310, 48, W - 296, 62], fill=CRIMSON)
    draw.text((W - 288, 46), "LIVE", font=sub, fill=MUTED)

    badge_f = _font(13, bold=True)
    bx = W - 52
    badges: list[tuple[str, tuple[int, int, int]]] = [(tier.upper(), heat)]
    if vuln.blast_radius == "critical":
        badges.append(("BLAST CRITICAL", CRIMSON))
    elif vuln.blast_radius == "elevated":
        badges.append(("BLAST ELEVATED", AMBER))
    if vuln.in_hosting_kev:
        badges.append(("HOSTING-KEV", AMBER))
    if vuln.in_kev:
        badges.append(("CISA KEV", CRIMSON))
    for label, color in badges:
        tw = int(draw.textlength(label, font=badge_f))
        bw = tw + 22
        bx -= bw + 8
        _rounded(draw, [bx, 70, bx + bw, 98], 8, color)
        draw.text((bx + 11, 76), label, font=badge_f, fill=INK)

    # Score gauge (left)
    gx, gy, gr = 170, 320, 118
    _gauge(draw, gx, gy, gr, score, heat)
    sf = _font(64, bold=True)
    st = f"{score:.0f}"
    sw = draw.textlength(st, font=sf)
    draw.text((gx - sw / 2, gy - 42), st, font=sf, fill=ICE)
    lf = _font(14, bold=True)
    lab = "SENTINEL SCORE"
    lw = draw.textlength(lab, font=lf)
    draw.text((gx - lw / 2, gy + 28), lab, font=lf, fill=MUTED)
    tf = _font(16, bold=True)
    tw = draw.textlength(tier.upper(), font=tf)
    draw.text((gx - tw / 2, gy + 50), tier.upper(), font=tf, fill=heat)

    # Threat density bar
    bar_x, bar_y, bar_w = 60, 480, 220
    _rounded(draw, [bar_x, bar_y, bar_x + bar_w, bar_y + 14], 7, PANEL2)
    fill = int(bar_w * max(0.0, min(100.0, score)) / 100.0)
    if fill > 8:
        _rounded(draw, [bar_x, bar_y, bar_x + fill, bar_y + 14], 7, heat)
    draw.text((bar_x, bar_y + 22), "THREAT DENSITY", font=sub, fill=MUTED)

    # Right content
    rx = 340
    mega = _font(36, bold=True)
    draw.text((rx, 120), sev.upper(), font=mega, fill=sev_color)

    title_f = _font(26, bold=True)
    title = (vuln.title or "Untitled finding").strip()
    for i, line in enumerate(_wrap(draw, title, title_f, W - rx - 60)[:3]):
        draw.text((rx, 170 + i * 34), line, font=title_f, fill=ICE)

    # Chips
    chip_f = _font(14, bold=True)
    cy = 280
    cx = rx
    cx = _chip(draw, cx, cy, f"CVSS {_fmt_cvss(vuln)}", chip_f, ICE, PANEL2)
    cx = _chip(draw, cx, cy, f"T{vuln.source_tier}", chip_f, TEAL, PANEL2)
    cx = _chip(draw, cx, cy, (vuln.category or "other").upper(), chip_f, ICE, PANEL2)
    cx = _chip(draw, cx, cy, (vuln.source or "?")[:18], chip_f, ICE, PANEL2)
    if vuln.version_applicable:
        _chip(draw, cx, cy, "FLEET MATCH", chip_f, GREEN, (20, 48, 36))
    else:
        _chip(draw, cx, cy, "NOT IN FLEET", chip_f, AMBER, (48, 40, 18))

    # Metric cards
    products = ", ".join(vuln.matched_products[:3]) if vuln.matched_products else "unmatched"
    cves = ", ".join(vuln.cve_ids[:3]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    card_y = 340
    card_h = 88
    card_w = 420
    _rounded(draw, [rx, card_y, rx + card_w, card_y + card_h], 14, PANEL2)
    draw.rectangle([rx, card_y, rx + 6, card_y + card_h], fill=TEAL)
    draw.text((rx + 22, card_y + 14), "MATCHED STACK", font=sub, fill=MUTED)
    draw.text((rx + 22, card_y + 40), products[:36], font=_font(22, bold=True), fill=ICE)

    _rounded(draw, [rx + card_w + 16, card_y, rx + card_w * 2 + 16, card_y + card_h], 14, PANEL2)
    draw.rectangle([rx + card_w + 16, card_y, rx + card_w + 22, card_y + card_h], fill=AMBER)
    draw.text((rx + card_w + 38, card_y + 14), "CVE / ADVISORY", font=sub, fill=MUTED)
    draw.text(
        (rx + card_w + 38, card_y + 40),
        cves[:36],
        font=_font(22, bold=True),
        fill=AMBER if (vuln.in_kev or vuln.in_hosting_kev) else ICE,
    )

    # Impact
    impact = (vuln.impact_note or "No hosting-specific impact note.").strip()
    _rounded(draw, [rx, 450, W - 52, 620], 14, PANEL2)
    draw.text((rx + 22, 464), "OPERATOR IMPACT", font=_font(13, bold=True), fill=TEAL)
    body = _font(18)
    iy = 494
    for line in _wrap(draw, impact, body, W - rx - 100)[:3]:
        draw.text((rx + 22, iy), line, font=body, fill=ICE)
        iy += 28

    # Footer
    foot = _font(13)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.line([(52, 640), (W - 52, 640)], fill=LINE, width=1)
    draw.text((52, 656), "sentinelwatch · shared-hosting early warning", font=foot, fill=MUTED)
    draw.text((520, 656), now, font=foot, fill=MUTED)
    bw = draw.textlength("BLACKRAINSENTINEL", font=foot)
    draw.text((W - 52 - bw, 656), "BLACKRAINSENTINEL", font=foot, fill=TEAL)

    return _encode_photo(img)


def render_digest_card(items: list[Vulnerability], title: str = "Daily Digest") -> bytes | None:
    if Image is None:
        return None

    img = Image.new("RGB", (W, H), INK)
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        draw.line([(0, y), (W, y)], fill=(10 + int(8 * t), 14 + int(10 * t), 22 + int(12 * t)))
    draw.rectangle([0, 0, 12, H], fill=TEAL)
    _rounded(draw, [28, 24, W - 28, H - 24], 20, PANEL)

    brand = _font(28, bold=True)
    sub = _font(16)
    draw.text((52, 44), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((52, 80), title.upper(), font=sub, fill=MUTED)
    count = f"{len(items)} ITEMS"
    cw = draw.textlength(count, font=brand)
    draw.text((W - 52 - cw, 48), count, font=brand, fill=ICE)

    y = 120
    body = _font(17)
    body_b = _font(20, bold=True)
    for v in items[:6]:
        sev = (v.severity_tier or "unknown").lower()
        color = _SEVERITY_COLOR.get(sev, MUTED)
        heat = _tier_heat(float(v.alert_score or 0))
        _rounded(draw, [52, y, W - 52, y + 72], 12, PANEL2)
        draw.rectangle([52, y, 64, y + 72], fill=color)
        score = f"{float(v.alert_score or 0):.0f}"
        draw.text((80, y + 20), score.rjust(3), font=body_b, fill=heat)
        flags = []
        if v.in_kev:
            flags.append("KEV")
        if v.in_hosting_kev:
            flags.append("H-KEV")
        head = (v.title or "")[:64]
        if flags:
            head = f"[{'|'.join(flags)}] {head}"
        draw.text((150, y + 14), head, font=body, fill=ICE)
        draw.text(
            (150, y + 42),
            f"{sev.upper()} · blast {v.blast_radius or '?'} · T{v.source_tier}",
            font=sub,
            fill=MUTED,
        )
        y += 84

    if len(items) > 6:
        draw.text((52, H - 48), f"+ {len(items) - 6} more in digest text", font=sub, fill=MUTED)

    return _encode_photo(img)
