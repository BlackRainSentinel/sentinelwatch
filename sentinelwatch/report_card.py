"""
Visual threat report cards for Telegram (PNG).

Design language: ink ops console — charcoal field, teal signal, amber hazard.
Not a generic CVE dump and not an exposure-map clone.
"""

from __future__ import annotations

import io
import math
from pathlib import Path

from sentinelwatch.models import Vulnerability

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFont = None  # type: ignore


# Palette — hosting-ops, not purple SaaS
INK = (8, 12, 18)
PANEL = (16, 24, 34)
PANEL2 = (22, 34, 48)
TEAL = (0, 210, 190)
TEAL_DIM = (0, 120, 110)
AMBER = (255, 176, 32)
CRIMSON = (255, 64, 72)
ICE = (230, 240, 248)
MUTED = (120, 140, 160)
LINE = (40, 58, 74)

_SEVERITY_COLOR = {
    "critical": CRIMSON,
    "high": AMBER,
    "medium": (64, 160, 255),
    "low": (80, 180, 120),
    "unknown": MUTED,
}


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = []
    if bold:
        candidates += [
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        ]
    candidates += [
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
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


def _rounded(draw: ImageDraw.ImageDraw, xy, radius: int, fill) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill)


def _score_arc(
    draw: ImageDraw.ImageDraw,
    cx: int,
    cy: int,
    r: int,
    score: float,
    color: tuple[int, int, int],
) -> None:
    # Background ring
    bbox = [cx - r, cy - r, cx + r, cy + r]
    draw.arc(bbox, start=140, end=400, fill=LINE, width=10)
    # Score ring (0-100 → 140° to 400°)
    span = 260 * max(0.0, min(100.0, score)) / 100.0
    draw.arc(bbox, start=140, end=140 + span, fill=color, width=10)
    # Inner glow disc
    draw.ellipse([cx - r + 22, cy - r + 22, cx + r - 22, cy + r - 22], fill=PANEL2)


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Return PNG bytes, or None if Pillow unavailable."""
    if Image is None:
        return None

    W, H = 1200, 680
    img = Image.new("RGB", (W, H), INK)
    draw = ImageDraw.Draw(img)

    # Atmospheric gradient strips
    for y in range(H):
        t = y / H
        r = int(INK[0] + (PANEL[0] - INK[0]) * t * 0.6)
        g = int(INK[1] + (PANEL[1] - INK[1]) * t * 0.6)
        b = int(INK[2] + (PANEL[2] - INK[2]) * t * 0.6)
        draw.line([(0, y), (W, y)], fill=(r, g, b))

    # Left hazard rail
    sev = (vuln.severity_tier or "unknown").lower()
    sev_color = _SEVERITY_COLOR.get(sev, MUTED)
    draw.rectangle([0, 0, 14, H], fill=sev_color)

    # Top brand bar
    _rounded(draw, [40, 28, W - 40, 100], 18, PANEL)
    brand = _font(36, bold=True)
    sub = _font(18)
    draw.text((64, 42), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((64, 82), "HOSTING THREAT BRIEFING", font=sub, fill=MUTED)

    # Live badges top-right
    bx = W - 64
    badges = []
    if vuln.in_kev:
        badges.append(("CISA KEV", CRIMSON))
    if vuln.in_hosting_kev:
        badges.append(("HOSTING-KEV", AMBER))
    if vuln.blast_radius == "critical":
        badges.append(("BLAST CRITICAL", CRIMSON))
    elif vuln.blast_radius == "elevated":
        badges.append(("BLAST ELEVATED", AMBER))
    for label, color in reversed(badges):
        tw = draw.textlength(label, font=sub)
        bx -= int(tw) + 36
        _rounded(draw, [bx, 48, bx + tw + 24, 80], 12, color)
        draw.text((bx + 12, 54), label, font=sub, fill=INK)

    # Main panel
    _rounded(draw, [40, 120, W - 40, H - 40], 22, PANEL)

    # Score gauge (right)
    score = float(vuln.alert_score or 0)
    gauge_color = CRIMSON if score >= 70 else AMBER if score >= 45 else TEAL
    _score_arc(draw, W - 190, 310, 110, score, gauge_color)
    score_font = _font(52, bold=True)
    label_font = _font(16)
    score_txt = f"{score:.0f}"
    sw = draw.textlength(score_txt, font=score_font)
    draw.text((W - 190 - sw / 2, 278), score_txt, font=score_font, fill=ICE)
    lw = draw.textlength("ALERT SCORE", font=label_font)
    draw.text((W - 190 - lw / 2, 340), "ALERT SCORE", font=label_font, fill=MUTED)

    # Severity mega label
    mega = _font(44, bold=True)
    draw.text((72, 148), sev.upper(), font=mega, fill=sev_color)

    # Title
    title_font = _font(28, bold=True)
    title = (vuln.title or "Untitled finding").strip()
    title_lines = _wrap(draw, title, title_font, W - 420)[:3]
    ty = 210
    for line in title_lines:
        draw.text((72, ty), line, font=title_font, fill=ICE)
        ty += 36

    # Meta row chips
    chip_font = _font(17, bold=True)
    chips = [
        f"CVSS {_fmt(vuln)}",
        f"T{vuln.source_tier}",
        (vuln.category or "other").upper(),
        (vuln.source or "?")[:22],
    ]
    if vuln.version_applicable:
        chips.append("APPLICABLE")
    else:
        chips.append("NOT IN FLEET VER")
    cx, cy = 72, ty + 18
    for chip in chips:
        tw = draw.textlength(chip, font=chip_font)
        _rounded(draw, [cx, cy, cx + tw + 28, cy + 34], 10, PANEL2)
        draw.text((cx + 14, cy + 7), chip, font=chip_font, fill=TEAL if chip.startswith("T") or chip == "APPLICABLE" else ICE)
        cx += int(tw) + 40

    # Divider
    draw.line([(72, cy + 56), (W - 280, cy + 56)], fill=LINE, width=2)

    # Products + CVE
    body = _font(20)
    body_b = _font(20, bold=True)
    y = cy + 76
    draw.text((72, y), "MATCHED STACK", font=label_font, fill=MUTED)
    products = ", ".join(vuln.matched_products[:4]) if vuln.matched_products else "unmatched / review manually"
    draw.text((72, y + 24), products[:70], font=body_b, fill=ICE)

    draw.text((72, y + 70), "CVE / ADVISORY", font=label_font, fill=MUTED)
    cves = ", ".join(vuln.cve_ids[:4]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    draw.text((72, y + 94), cves[:70], font=body_b, fill=AMBER if vuln.in_kev or vuln.in_hosting_kev else ICE)

    # Impact callout
    impact = (vuln.impact_note or "No hosting-specific impact note for this product match.").strip()
    _rounded(draw, [72, H - 170, W - 280, H - 70], 14, PANEL2)
    draw.text((92, H - 158), "OPERATOR IMPACT", font=label_font, fill=TEAL)
    impact_lines = _wrap(draw, impact, body, W - 400)[:2]
    iy = H - 130
    for line in impact_lines:
        draw.text((92, iy), line, font=body, fill=ICE)
        iy += 26

    # Footer
    foot = _font(15)
    draw.text((72, H - 58), "sentinelwatch · shared-hosting early warning", font=foot, fill=MUTED)
    draw.text((W - 280, H - 58), "BLACKRAINSENTINEL", font=foot, fill=TEAL_DIM)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _fmt(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def render_digest_card(items: list[Vulnerability], title: str = "Daily Digest") -> bytes | None:
    if Image is None:
        return None
    W, H = 1200, 720
    img = Image.new("RGB", (W, H), INK)
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        draw.line(
            [(0, y), (W, y)],
            fill=(
                int(8 + 10 * t),
                int(12 + 14 * t),
                int(18 + 18 * t),
            ),
        )
    draw.rectangle([0, 0, 14, H], fill=TEAL)
    _rounded(draw, [40, 28, W - 40, H - 40], 22, PANEL)
    brand = _font(34, bold=True)
    sub = _font(18)
    body = _font(20)
    body_b = _font(20, bold=True)
    draw.text((72, 56), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((72, 100), title.upper(), font=sub, fill=MUTED)
    draw.text((W - 220, 64), f"{len(items)} ITEMS", font=brand, fill=ICE)

    y = 150
    for v in items[:9]:
        sev = (v.severity_tier or "unknown").lower()
        color = _SEVERITY_COLOR.get(sev, MUTED)
        _rounded(draw, [72, y, W - 72, y + 52], 12, PANEL2)
        draw.rectangle([72, y, 86, y + 52], fill=color)
        score = f"{v.alert_score:.0f}"
        draw.text((100, y + 14), score.rjust(3), font=body_b, fill=color)
        flags = []
        if v.in_kev:
            flags.append("KEV")
        if v.in_hosting_kev:
            flags.append("H-KEV")
        head = (v.title or "")[:68]
        if flags:
            head = f"[{'|'.join(flags)}] {head}"
        draw.text((160, y + 14), head, font=body, fill=ICE)
        y += 60

    if len(items) > 9:
        draw.text((72, H - 70), f"+ {len(items) - 9} more in full digest text", font=sub, fill=MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
