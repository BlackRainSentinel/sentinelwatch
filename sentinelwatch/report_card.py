"""
Visual threat briefing cards for Telegram (high-res PNG).

HUD / ops-console language: deep ink field, teal signal, amber hazard,
score-tier heat. Rendered at 2× for sharp Telegram display.
"""

from __future__ import annotations

import io
import math
from datetime import datetime, timezone
from pathlib import Path

from sentinelwatch.models import Vulnerability

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageFont = None  # type: ignore


# ── Palette ──────────────────────────────────────────────────────────
INK = (6, 10, 16)
PANEL = (14, 22, 32)
PANEL2 = (20, 32, 46)
PANEL3 = (28, 44, 62)
TEAL = (0, 220, 200)
TEAL_DIM = (0, 110, 100)
TEAL_GLOW = (0, 180, 165)
AMBER = (255, 186, 40)
CRIMSON = (255, 58, 68)
ICE = (236, 244, 252)
MUTED = (110, 132, 154)
LINE = (38, 56, 74)
GREEN = (64, 210, 140)

_SEVERITY_COLOR = {
    "critical": CRIMSON,
    "high": AMBER,
    "medium": (72, 168, 255),
    "low": GREEN,
    "unknown": MUTED,
}

# Canvas — 2× so Telegram compression still looks crisp
W, H = 2560, 1440


def score_tier(score: float) -> str:
    """Map alert score → visual/caption tier."""
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
        "severe": (255, 96, 48),
        "elevated": AMBER,
        "moderate": (72, 168, 255),
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


def _blend(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        int(a[0] + (b[0] - a[0]) * t),
        int(a[1] + (b[1] - a[1]) * t),
        int(a[2] + (b[2] - a[2]) * t),
    )


def _paint_atmosphere(img: Image.Image, heat: tuple[int, int, int]) -> None:
    """Vertical wash + soft heat bloom + grid."""
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        base = _blend(INK, PANEL, t * 0.55)
        wash = _blend(base, heat, 0.05 * (1.0 - t) + 0.02)
        draw.line([(0, y), (W, y)], fill=wash)

    # Diagonal scan sheen (subtle)
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    for i in range(0, W + H, 36):
        od.line([(i, 0), (i - H, H)], fill=(255, 255, 255, 8), width=1)
    composed = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
    img.paste(composed)

    # Fine grid
    g = ImageDraw.Draw(img)
    for x in range(80, W, 80):
        g.line([(x, 0), (x, H)], fill=LINE, width=1)
    for y in range(80, H, 80):
        g.line([(0, y), (W, y)], fill=LINE, width=1)


def _hud_brackets(draw: ImageDraw.ImageDraw, x0: int, y0: int, x1: int, y1: int, color, arm: int = 36) -> None:
    """Corner HUD marks."""
    w = 4
    # TL
    draw.line([(x0, y0 + arm), (x0, y0), (x0 + arm, y0)], fill=color, width=w)
    # TR
    draw.line([(x1 - arm, y0), (x1, y0), (x1, y0 + arm)], fill=color, width=w)
    # BL
    draw.line([(x0, y1 - arm), (x0, y1), (x0 + arm, y1)], fill=color, width=w)
    # BR
    draw.line([(x1 - arm, y1), (x1, y1), (x1, y1 - arm)], fill=color, width=w)


def _score_gauge(
    base: Image.Image,
    cx: int,
    cy: int,
    r: int,
    score: float,
    color: tuple[int, int, int],
) -> None:
    """Thick ring with tick marks + glow layer."""
    glow = Image.new("RGBA", base.size, (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    bbox = [cx - r - 8, cy - r - 8, cx + r + 8, cy + r + 8]
    span = 270 * max(0.0, min(100.0, score)) / 100.0
    gd.arc(bbox, start=135, end=135 + span, fill=(*color, 100), width=32)
    glow = glow.filter(ImageFilter.GaussianBlur(22))
    composed = Image.alpha_composite(base.convert("RGBA"), glow).convert("RGB")
    base.paste(composed)

    draw = ImageDraw.Draw(base)
    outer = [cx - r, cy - r, cx + r, cy + r]
    draw.arc(outer, start=135, end=405, fill=LINE, width=18)
    draw.arc(outer, start=135, end=135 + span, fill=color, width=18)

    # Tick marks
    for i in range(0, 11):
        ang = math.radians(135 + 27 * i)
        x0 = cx + (r - 28) * math.cos(ang)
        y0 = cy + (r - 28) * math.sin(ang)
        x1 = cx + (r - 12) * math.cos(ang)
        y1 = cy + (r - 12) * math.sin(ang)
        tick = color if i <= score / 10 else MUTED
        draw.line([(x0, y0), (x1, y1)], fill=tick, width=3)

    # Inner disc
    draw.ellipse([cx - r + 42, cy - r + 42, cx + r - 42, cy + r - 42], fill=PANEL2, outline=PANEL3, width=2)
    # Pulse dots
    for i, a in enumerate((200, 260, 320)):
        ang = math.radians(a)
        px = cx + (r - 8) * math.cos(ang)
        py = cy + (r - 8) * math.sin(ang)
        rr = 5 if i == 0 else 4
        draw.ellipse([px - rr, py - rr, px + rr, py + rr], fill=TEAL if i else color)


def _chip(draw, x: int, y: int, label: str, font, fg, bg, pad_x: int = 22, h: int = 48) -> int:
    tw = draw.textlength(label, font=font)
    w = int(tw) + pad_x * 2
    _rounded(draw, [x, y, x + w, y + h], 14, bg, outline=LINE, width=1)
    draw.text((x + pad_x, y + 10), label, font=font, fill=fg)
    return x + w + 16


def _metric_block(draw, x: int, y: int, w: int, h: int, label: str, value: str, accent) -> None:
    _rounded(draw, [x, y, x + w, y + h], 18, PANEL2, outline=LINE, width=2)
    draw.rectangle([x, y, x + 8, y + h], fill=accent)
    lf = _font(22)
    vf = _font(34, bold=True)
    draw.text((x + 28, y + 22), label, font=lf, fill=MUTED)
    # wrap value
    lines = _wrap(draw, value, vf, w - 56)[:2]
    vy = y + 58
    for line in lines:
        draw.text((x + 28, vy), line, font=vf, fill=ICE)
        vy += 40


def _fmt_cvss(vuln: Vulnerability) -> str:
    if vuln.cvss_score is None:
        return "n/a"
    return f"{vuln.cvss_score:.1f}"


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Return high-res PNG bytes, or None if Pillow unavailable."""
    if Image is None:
        return None

    score = float(vuln.alert_score or 0)
    heat = _tier_heat(score)
    sev = (vuln.severity_tier or "unknown").lower()
    sev_color = _SEVERITY_COLOR.get(sev, MUTED)
    tier = score_tier(score)

    img = Image.new("RGB", (W, H), INK)
    _paint_atmosphere(img, heat)
    draw = ImageDraw.Draw(img)

    # Left severity rail (thick)
    draw.rectangle([0, 0, 28, H], fill=sev_color)
    # Heat accent strip
    draw.rectangle([28, 0, 36, H], fill=_blend(sev_color, INK, 0.55))

    # Outer frame
    margin = 56
    _hud_brackets(draw, margin, margin, W - margin, H - margin, TEAL_DIM, arm=48)
    _rounded(draw, [margin + 12, margin + 12, W - margin - 12, H - margin - 12], 28, PANEL, outline=LINE, width=2)

    # ── Header ────────────────────────────────────────────────────
    brand = _font(56, bold=True)
    sub = _font(26)
    micro = _font(22)
    draw.text((100, 92), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((100, 158), "SHARED-HOSTING THREAT BRIEFING  ·  LIVE", font=sub, fill=MUTED)

    # Live pulse
    draw.ellipse([W - 420, 118, W - 400, 138], fill=CRIMSON)
    draw.text((W - 388, 112), "SIGNAL ACTIVE", font=micro, fill=MUTED)

    # Badges
    badge_font = _font(24, bold=True)
    bx = W - 100
    badges: list[tuple[str, tuple[int, int, int]]] = []
    if vuln.in_kev:
        badges.append(("CISA KEV", CRIMSON))
    if vuln.in_hosting_kev:
        badges.append(("HOSTING-KEV", AMBER))
    if vuln.blast_radius == "critical":
        badges.append(("BLAST CRITICAL", CRIMSON))
    elif vuln.blast_radius == "elevated":
        badges.append(("BLAST ELEVATED", AMBER))
    badges.append((tier.upper(), heat))
    for label, color in reversed(badges):
        tw = draw.textlength(label, font=badge_font)
        bw = int(tw) + 40
        bx -= bw + 18
        _rounded(draw, [bx, 170, bx + bw, 220], 14, color)
        draw.text((bx + 20, 180), label, font=badge_font, fill=INK)

    # Divider under header
    draw.line([(100, 250), (W - 100, 250)], fill=LINE, width=2)
    # Teal accent underline under brand
    draw.rectangle([100, 248, 420, 254], fill=TEAL)

    # ── Score column (left) ───────────────────────────────────────
    gx, gy, gr = 340, 620, 200
    _score_gauge(img, gx, gy, gr, score, heat)
    draw = ImageDraw.Draw(img)

    score_font = _font(110, bold=True)
    score_txt = f"{score:.0f}"
    sw = draw.textlength(score_txt, font=score_font)
    draw.text((gx - sw / 2, gy - 78), score_txt, font=score_font, fill=ICE)
    lab = _font(28, bold=True)
    lw = draw.textlength("ALERT SCORE", font=lab)
    draw.text((gx - lw / 2, gy + 40), "ALERT SCORE", font=lab, fill=MUTED)
    tw = draw.textlength(tier.upper(), font=lab)
    draw.text((gx - tw / 2, gy + 82), tier.upper(), font=lab, fill=heat)

    # Threat bar under gauge
    bar_x0, bar_y0, bar_w = 140, 900, 400
    _rounded(draw, [bar_x0, bar_y0, bar_x0 + bar_w, bar_y0 + 28], 10, PANEL3)
    fill_w = int(bar_w * max(0.0, min(100.0, score)) / 100.0)
    if fill_w > 16:
        _rounded(draw, [bar_x0, bar_y0, bar_x0 + fill_w, bar_y0 + 28], 10, heat)
    draw.text((bar_x0, bar_y0 + 44), "THREAT INTENSITY", font=micro, fill=MUTED)

    # Severity mega
    mega = _font(72, bold=True)
    draw.text((620, 290), sev.upper(), font=mega, fill=sev_color)

    # Title
    title_font = _font(44, bold=True)
    title = (vuln.title or "Untitled finding").strip()
    title_lines = _wrap(draw, title, title_font, W - 720)[:3]
    ty = 380
    for line in title_lines:
        draw.text((620, ty), line, font=title_font, fill=ICE)
        ty += 56

    # Meta chips
    chip_font = _font(26, bold=True)
    chips = [
        (f"CVSS {_fmt_cvss(vuln)}", ICE, PANEL3),
        (f"T{vuln.source_tier}", TEAL, PANEL3),
        ((vuln.category or "other").upper(), ICE, PANEL3),
        ((vuln.source or "?")[:24], ICE, PANEL3),
    ]
    if vuln.version_applicable:
        chips.append(("FLEET MATCH", GREEN, (18, 48, 36)))
    else:
        chips.append(("NOT IN FLEET VER", AMBER, (48, 40, 18)))
    cx, cy = 620, ty + 24
    for label, fg, bg in chips:
        cx = _chip(draw, cx, cy, label, chip_font, fg, bg, pad_x=20, h=52)

    # Metric blocks
    my = cy + 90
    block_w = 520
    products = ", ".join(vuln.matched_products[:4]) if vuln.matched_products else "unmatched / review"
    cves = ", ".join(vuln.cve_ids[:4]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    _metric_block(draw, 620, my, block_w, 150, "MATCHED STACK", products[:48], TEAL)
    _metric_block(
        draw,
        620 + block_w + 28,
        my,
        block_w,
        150,
        "CVE / ADVISORY",
        cves[:48],
        AMBER if (vuln.in_kev or vuln.in_hosting_kev) else TEAL,
    )

    # Blast + channel strip
    info_font = _font(28)
    info_b = _font(28, bold=True)
    iy = my + 180
    draw.text((620, iy), "BLAST RADIUS", font=micro, fill=MUTED)
    draw.text((620, iy + 36), (vuln.blast_radius or "normal").upper(), font=info_b, fill=heat)
    draw.text((980, iy), "CHANNEL", font=micro, fill=MUTED)
    draw.text((980, iy + 36), (vuln.channel or "critical").upper(), font=info_b, fill=ICE)
    draw.text((1320, iy), "SOURCE TIER", font=micro, fill=MUTED)
    draw.text((1320, iy + 36), f"T{vuln.source_tier}", font=info_b, fill=TEAL)

    # Operator impact panel
    impact = (vuln.impact_note or "No hosting-specific impact note for this product match.").strip()
    _rounded(draw, [620, 1080, W - 100, 1280], 22, PANEL2, outline=_blend(TEAL, LINE, 0.5), width=2)
    draw.text((656, 1100), "OPERATOR IMPACT", font=_font(24, bold=True), fill=TEAL)
    body = _font(30)
    impact_lines = _wrap(draw, impact, body, W - 780)[:3]
    iy = 1148
    for line in impact_lines:
        draw.text((656, iy), line, font=body, fill=ICE)
        iy += 40

    # Footer
    foot = _font(24)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.line([(100, 1320), (W - 100, 1320)], fill=LINE, width=2)
    draw.text((100, 1348), "sentinelwatch  ·  shared-hosting early warning", font=foot, fill=MUTED)
    draw.text((1000, 1348), now, font=foot, fill=MUTED)
    brand_w = draw.textlength("BLACKRAINSENTINEL", font=foot)
    draw.text((W - 100 - brand_w, 1348), "BLACKRAINSENTINEL", font=foot, fill=TEAL_DIM)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def render_digest_card(items: list[Vulnerability], title: str = "Daily Digest") -> bytes | None:
    if Image is None:
        return None

    img = Image.new("RGB", (W, H), INK)
    _paint_atmosphere(img, TEAL)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 28, H], fill=TEAL)
    _hud_brackets(draw, 56, 56, W - 56, H - 56, TEAL_DIM, arm=48)
    _rounded(draw, [68, 68, W - 68, H - 68], 28, PANEL, outline=LINE, width=2)

    brand = _font(56, bold=True)
    sub = _font(28)
    body = _font(32)
    body_b = _font(32, bold=True)
    draw.text((120, 110), "SENTINELWATCH", font=brand, fill=TEAL)
    draw.text((120, 180), title.upper(), font=sub, fill=MUTED)
    count = f"{len(items)} ITEMS"
    cw = draw.textlength(count, font=brand)
    draw.text((W - 120 - cw, 120), count, font=brand, fill=ICE)

    y = 260
    for v in items[:8]:
        sev = (v.severity_tier or "unknown").lower()
        color = _SEVERITY_COLOR.get(sev, MUTED)
        heat = _tier_heat(float(v.alert_score or 0))
        _rounded(draw, [120, y, W - 120, y + 110], 18, PANEL2, outline=LINE, width=1)
        draw.rectangle([120, y, 148, y + 110], fill=color)
        score = f"{v.alert_score:.0f}"
        draw.text((180, y + 28), score.rjust(3), font=_font(48, bold=True), fill=heat)
        flags = []
        if v.in_kev:
            flags.append("KEV")
        if v.in_hosting_kev:
            flags.append("H-KEV")
        head = (v.title or "")[:72]
        if flags:
            head = f"[{'|'.join(flags)}] {head}"
        draw.text((340, y + 24), head, font=body, fill=ICE)
        meta = f"{sev.upper()}  ·  blast {(v.blast_radius or '?')}  ·  T{v.source_tier}"
        draw.text((340, y + 68), meta, font=sub, fill=MUTED)
        y += 128

    if len(items) > 8:
        draw.text((120, H - 120), f"+ {len(items) - 8} more in full digest text", font=sub, fill=MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
