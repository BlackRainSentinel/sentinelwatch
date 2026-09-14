"""
SentinelWatch threat art — cinematic 'Black Rain' posters for Telegram.

The image is a visual identity piece (rain field, hazard geometry, score
silhouette). Structured facts live primarily in the caption.
"""

from __future__ import annotations

import hashlib
import io
import logging
import math
import random
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from sentinelwatch.models import Vulnerability

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageFont = None  # type: ignore

log = logging.getLogger(__name__)

# Square — fills Telegram chat aggressively
W, H = 1280, 1280

BG = (6, 8, 14)
INK = (248, 250, 252)
DIM = (150, 162, 178)
TEAL = (0, 220, 205)
TEAL_DEEP = (0, 90, 85)
CRIMSON = (255, 48, 68)
AMBER = (255, 186, 40)
GREEN = (64, 220, 150)


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


def _font(size: int, *, black: bool = False, bold: bool = False) -> ImageFont.ImageFont:
    paths: list[str] = []
    if black:
        paths += [
            "/usr/share/fonts/truetype/noto/NotoSansDisplay-Black.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Black.ttf",
        ]
    if bold or black:
        paths += [
            "/usr/share/fonts/truetype/noto/NotoSansDisplay-Bold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
    paths += [
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for p in paths:
        if Path(p).is_file():
            try:
                return ImageFont.truetype(p, size)
            except OSError:
                continue
    return ImageFont.load_default()


def _mono(size: int) -> ImageFont.ImageFont:
    for p in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        if Path(p).is_file():
            try:
                return ImageFont.truetype(p, size)
            except OSError:
                continue
    return _font(size, bold=True)


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_w: int) -> list[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines: list[str] = []
    cur = words[0]
    for w in words[1:]:
        trial = f"{cur} {w}"
        if draw.textlength(trial, font=font) <= max_w:
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


def _seed(vuln: Vulnerability) -> int:
    key = f"{vuln.external_id}|{vuln.cve_ids}|{vuln.alert_score}"
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)


def _paint_atmosphere(base: Image.Image, heat: tuple[int, int, int], rng: random.Random) -> None:
    """Black Rain field — brand-unique weather, not a UI grid."""
    draw = ImageDraw.Draw(base)
    # vertical depth wash
    for y in range(H):
        t = y / H
        r = int(BG[0] + heat[0] * 0.07 * (1 - t) + 10 * t)
        g = int(BG[1] + heat[1] * 0.04 * (1 - t) + 12 * t)
        b = int(BG[2] + heat[2] * 0.05 * (1 - t) + 16 * t)
        draw.line([(0, y), (W, y)], fill=(min(255, r), min(255, g), min(255, b)))

    # rain streaks (seeded → unique per CVE)
    rain = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    rd = ImageDraw.Draw(rain)
    for _ in range(180):
        x = rng.randint(-40, W + 40)
        y = rng.randint(-40, H)
        length = rng.randint(28, 90)
        alpha = rng.randint(18, 55)
        color = (*TEAL, alpha) if rng.random() > 0.35 else (180, 200, 220, alpha // 2)
        rd.line([(x, y), (x + length * 0.25, y + length)], fill=color, width=rng.choice([1, 1, 2]))
    base.paste(Image.alpha_composite(base.convert("RGBA"), rain).convert("RGB"))

    # soft hazard bloom top-right
    bloom = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bloom)
    bd.ellipse([W - 520, -180, W + 180, 520], fill=(*heat, 55))
    bloom = bloom.filter(ImageFilter.GaussianBlur(90))
    base.paste(Image.alpha_composite(base.convert("RGBA"), bloom).convert("RGB"))


def _hazard_slash(draw: ImageDraw.ImageDraw, color: tuple[int, int, int]) -> None:
    # Dramatic diagonal band
    pts = [(W * 0.55, -40), (W + 40, -40), (W + 40, H * 0.22), (W * 0.35, H * 0.55)]
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    od.polygon(pts, fill=(*color, 38))
    # thin bright edge
    od.line([(W * 0.55, -40), (W * 0.35, H * 0.55)], fill=(*color, 160), width=4)


def _score_silhouette(draw: ImageDraw.ImageDraw, score: float, color: tuple[int, int, int]) -> None:
    """Giant ghost score behind the title — the art centerpiece."""
    f = _font(420, black=True)
    txt = f"{score:.0f}"
    # outline-ish by stacking offsets in dim color
    cx, cy = W // 2 - 40, H // 2 - 80
    tw = draw.textlength(txt, font=f)
    x = cx - tw / 2
    for dx, dy in ((-3, 0), (3, 0), (0, -3), (0, 3), (0, 0)):
        fill = (*color, ) if False else (color[0] // 5, color[1] // 5, color[2] // 5)
        draw.text((x + dx, cy + dy), txt, font=f, fill=fill)


def _glass_panel(draw, xy, radius: int = 28) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=(18, 26, 40), outline=(55, 75, 100), width=2)


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Creative Black Rain poster → sharp Telegram JPEG."""
    if Image is None:
        return None

    score = float(vuln.alert_score or 0)
    sev = (vuln.severity_tier or "unknown").lower()
    heat = {
        "critical": CRIMSON,
        "high": AMBER,
        "medium": (80, 160, 255),
        "low": GREEN,
        "unknown": DIM,
    }.get(sev, CRIMSON)
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Confirm exposure on your shared-hosting stack."
    cve = ", ".join(vuln.cve_ids[:2]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    stack = ", ".join(vuln.matched_products[:2]) if vuln.matched_products else "review"
    rng = random.Random(_seed(vuln))

    # Draw at 2× then downscale — survives Telegram recompression better
    scale = 2
    sw, sh = W * scale, H * scale
    img = Image.new("RGB", (sw, sh), BG)

    # Temporarily work in logical coords via resize at end — draw on hi-res
    # Simpler: draw directly at 2× with fonts * scale
    def F(size: int, **kw):
        return _font(size * scale, **kw)

    def M(size: int):
        return _mono(size * scale)

    # Atmosphere on hi-res
    hi = Image.new("RGB", (sw, sh), BG)
    # scale atmosphere by drawing on logical then upscale? Draw rain on hi-res.
    draw0 = ImageDraw.Draw(hi)
    for y in range(sh):
        t = y / sh
        r = int(BG[0] + heat[0] * 0.08 * (1 - t) + 12 * t)
        g = int(BG[1] + heat[1] * 0.05 * (1 - t) + 14 * t)
        b = int(BG[2] + heat[2] * 0.06 * (1 - t) + 18 * t)
        draw0.line([(0, y), (sw, y)], fill=(min(255, r), min(255, g), min(255, b)))

    rain = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    rd = ImageDraw.Draw(rain)
    for _ in range(320):
        x = rng.randint(-80, sw + 80)
        y = rng.randint(-80, sh)
        length = rng.randint(50, 160) * scale // 2
        alpha = rng.randint(20, 60)
        col = (*TEAL, alpha) if rng.random() > 0.3 else (190, 210, 230, alpha // 2)
        rd.line([(x, y), (x + length * 0.22, y + length)], fill=col, width=max(1, scale))
    hi = Image.alpha_composite(hi.convert("RGBA"), rain).convert("RGB")

    bloom = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bloom)
    bd.ellipse([sw - 900, -300, sw + 300, 900], fill=(*heat, 60))
    bloom = bloom.filter(ImageFilter.GaussianBlur(120))
    hi = Image.alpha_composite(hi.convert("RGBA"), bloom).convert("RGB")

    # Diagonal slash
    slash = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    sd = ImageDraw.Draw(slash)
    sd.polygon(
        [
            (sw * 0.52, 0),
            (sw, 0),
            (sw, sh * 0.28),
            (sw * 0.28, sh * 0.62),
        ],
        fill=(*heat, 42),
    )
    sd.line([(sw * 0.52, 0), (sw * 0.28, sh * 0.62)], fill=(*heat, 180), width=5 * scale)
    hi = Image.alpha_composite(hi.convert("RGBA"), slash).convert("RGB")

    draw = ImageDraw.Draw(hi)

    # Giant score watermark
    sf = F(400, black=True)
    st = f"{score:.0f}"
    tw = draw.textlength(st, font=sf)
    sx = (sw - tw) / 2
    sy = sh * 0.22
    ghost = (heat[0] // 4 + 8, heat[1] // 6 + 8, heat[2] // 6 + 10)
    draw.text((sx, sy), st, font=sf, fill=ghost)

    # Radar rings (art, not a UI gauge)
    cx, cy = int(sw * 0.78), int(sh * 0.78)
    for i, rad in enumerate((90, 160, 240, 330)):
        r = rad * scale
        col = (0, 100 + i * 25, 110)
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=col, width=2 * scale)
    r = 240 * scale
    span = 270 * min(100.0, score) / 100.0
    draw.arc([cx - r, cy - r, cx + r, cy + r], start=-90, end=-90 + span, fill=heat, width=10 * scale)

    # Top brand
    pad = 56 * scale
    draw.text((pad, 48 * scale), "SENTINELWATCH", font=F(28, bold=True), fill=TEAL)
    draw.text((pad, 88 * scale), "BLACK RAIN  ·  HOSTING ALERT", font=F(18, bold=True), fill=DIM)

    # KEV / severity ribbon
    ribbon = "CRITICAL"
    if vuln.in_kev:
        ribbon = "CISA KEV  ·  ACTIVELY EXPLOITED"
    elif vuln.in_hosting_kev:
        ribbon = "HOSTING KEV"
    rf = F(22, black=True)
    rw = draw.textlength(ribbon, font=rf) + 56 * scale
    rx = sw - pad - rw
    draw.rounded_rectangle(
        [rx, 52 * scale, rx + rw, 108 * scale],
        radius=16 * scale,
        fill=heat,
    )
    draw.text((rx + 28 * scale, 66 * scale), ribbon, font=rf, fill=(10, 6, 8))

    # Glass title plate — height fits content (no empty void)
    title_f = F(52, black=True)
    sum_f = F(26)
    title_lines = _wrap(draw, headline, title_f, sw - pad * 2 - 48 * scale)[:3]
    sum_lines = _wrap(draw, summary, sum_f, sw - pad * 2 - 48 * scale)[:2]
    plate_h = (36 + len(title_lines) * 62 + 16 + len(sum_lines) * 36 + 40) * scale
    plate_top = int(sh * 0.50)
    draw.rounded_rectangle(
        [pad, plate_top, sw - pad, plate_top + plate_h],
        radius=32 * scale,
        fill=(14, 22, 36),
        outline=(70, 95, 120),
        width=3 * scale,
    )
    draw.rectangle(
        [pad, plate_top, pad + 12 * scale, plate_top + plate_h],
        fill=TEAL,
    )

    ty = plate_top + 36 * scale
    for line in title_lines:
        draw.text((pad + 36 * scale, ty), line, font=title_f, fill=INK)
        ty += 62 * scale
    ty += 8 * scale
    for line in sum_lines:
        draw.text((pad + 36 * scale, ty), line, font=sum_f, fill=DIM)
        ty += 36 * scale

    # Bottom stamp row
    by = sh - 200 * scale
    chips = [
        (cve, AMBER),
        (stack, TEAL),
        (f"CVSS {_fmt_cvss(vuln)}", INK),
        (f"SCORE {score:.0f}", heat),
    ]
    if vuln.version_applicable:
        chips.append(("FLEET OK", GREEN))
    else:
        chips.append(("FLEET GAP", AMBER))

    cx_chip = pad
    cf = F(20, bold=True)
    for label, col in chips:
        tw = draw.textlength(label, font=cf)
        cw = tw + 40 * scale
        ch = 52 * scale
        if cx_chip + cw > sw - pad:
            break
        draw.rounded_rectangle(
            [cx_chip, by, cx_chip + cw, by + ch],
            radius=14 * scale,
            fill=(22, 32, 48),
            outline=col,
            width=3 * scale,
        )
        draw.text((cx_chip + 20 * scale, by + 12 * scale), label, font=cf, fill=col)
        cx_chip += cw + 16 * scale

    # Footer wordmark
    draw.text((pad, sh - 70 * scale), "BLACKRAINSENTINEL", font=F(18, bold=True), fill=TEAL_DEEP)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tsw = draw.textlength(ts, font=F(16))
    draw.text((sw - pad - tsw, sh - 70 * scale), ts, font=F(16), fill=DIM)

    # Downscale to Telegram size with Lanczos
    out = hi.resize((W, H), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    out.save(buf, format="JPEG", quality=95, optimize=True, progressive=True, subsampling=0)
    return buf.getvalue()


def render_alert_card_png(vuln: Vulnerability) -> bytes | None:
    jpeg = render_alert_card(vuln)
    if not jpeg or Image is None:
        return None
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    big = img.resize((W * 2, H * 2), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    big.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def build_alert_html(vuln: Vulnerability) -> str:
    headline, summary = _split_title(vuln.title or "")
    return (
        f"<!DOCTYPE html><html><body style='background:#080a0e;color:#fff;font-family:sans-serif'>"
        f"<p>Black Rain poster (Pillow). Preview via render_alert_card.</p>"
        f"<h1>{escape(headline)}</h1><p>{escape(summary)}</p>"
        f"<p>{escape(', '.join(vuln.cve_ids) or vuln.external_id)}</p>"
        f"</body></html>"
    )


def write_alert_sources(vuln: Vulnerability, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "alert_card.html"
    png_path = out / "alert_card.png"
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
    draw.rectangle([0, 0, W, 90], fill=TEAL)
    draw.text((48, 28), "SENTINELWATCH DIGEST", font=_font(28, black=True), fill=BG)
    draw.text((48, 120), title.upper(), font=_font(22, bold=True), fill=DIM)
    draw.text((48, 160), f"{len(items)} findings", font=_font(56, black=True), fill=INK)
    y = 260
    for v in items[:7]:
        sev = (v.severity_tier or "unknown").lower()
        heat = CRIMSON if sev == "critical" else AMBER if sev == "high" else TEAL
        draw.rectangle([48, y, 56, y + 88], fill=heat)
        draw.text((72, y + 8), f"{float(v.alert_score or 0):.0f}", font=_font(36, black=True), fill=heat)
        for i, line in enumerate(_wrap(draw, v.title or "", _font(24, bold=True), W - 220)[:2]):
            draw.text((180, y + 10 + i * 30), line, font=_font(24, bold=True), fill=INK)
        y += 110
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92, optimize=True, subsampling=0)
    return buf.getvalue()
