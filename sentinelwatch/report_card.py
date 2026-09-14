"""
Threat briefing cards — editorial poster for Telegram.

Concept: Swiss / war-room bulletin. Typography does the work.
No dashboard chrome, no gauges, no nested empty cards.
Portrait 1080×1440 fills Telegram chat wider than landscape 16:9.
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

# Portrait — reads large in Telegram (landscape gets shrunk)
W, H = 1080, 1440

BG = (8, 10, 14)
SURFACE = (16, 20, 28)
INK = (250, 252, 255)
DIM = (140, 150, 165)
TEAL = (0, 210, 190)
CRIMSON = (255, 52, 64)
AMBER = (255, 180, 40)
GREEN = (60, 210, 140)
RULE = (40, 48, 62)

_SEVERITY = {
    "critical": (CRIMSON, "CRITICAL"),
    "high": (AMBER, "HIGH"),
    "medium": ((80, 160, 255), "MEDIUM"),
    "low": (GREEN, "LOW"),
    "unknown": (DIM, "UNKNOWN"),
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
    paths: list[str] = []
    if bold:
        paths += [
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        ]
    paths += [
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
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
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
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


def render_alert_card(vuln: Vulnerability) -> bytes | None:
    """Portrait editorial poster → Telegram JPEG."""
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
    fleet = "Yes — matches fleet" if vuln.version_applicable else "No — not in fleet versions"
    impact = (vuln.impact_note or "No hosting-specific impact note is available.").strip()
    blast = (vuln.blast_radius or "normal").upper()
    tier = {1: "Official", 2: "Research", 3: "Aggregator"}.get(int(vuln.source_tier or 3), "?")

    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    pad = 56
    content_w = W - pad * 2
    y = 0

    # ── Top urgency strip (only real signals) ─────────────────────
    strip_h = 72
    draw.rectangle([0, 0, W, strip_h], fill=sev_color)
    strip_txt = sev_label
    if vuln.in_kev:
        strip_txt = f"{sev_label}  ·  CISA KEV — ACTIVELY EXPLOITED"
    elif vuln.in_hosting_kev:
        strip_txt = f"{sev_label}  ·  HOSTING KEV"
    sf = _font(26, bold=True)
    sw = draw.textlength(strip_txt, font=sf)
    draw.text(((W - sw) / 2, 22), strip_txt, font=sf, fill=(12, 8, 10))
    y = strip_h + 40

    # Brand
    draw.text((pad, y), "SENTINELWATCH", font=_font(22, bold=True), fill=TEAL)
    y += 32
    draw.text((pad, y), "HOSTING THREAT BRIEFING", font=_font(18, bold=True), fill=DIM)
    y += 56

    # Giant score block — typography, not a toy gauge
    draw.text((pad, y), "SENTINEL SCORE", font=_font(18, bold=True), fill=DIM)
    y += 28
    score_f = _font(140, bold=True)
    draw.text((pad, y - 10), f"{score:.0f}", font=score_f, fill=INK)
    # CVSS beside score
    side_x = pad + 340
    draw.text((side_x, y + 24), "CVSS", font=_font(18, bold=True), fill=DIM)
    draw.text((side_x, y + 50), _fmt_cvss(vuln), font=_font(56, bold=True), fill=INK)
    draw.text((side_x, y + 120), "industry · separate", font=_font(16), fill=DIM)
    y += 170

    # Rule
    draw.rectangle([pad, y, W - pad, y + 3], fill=sev_color)
    y += 36

    # Headline — the product of the poster
    hf = _font(54, bold=True)
    for line in _wrap(draw, headline, hf, content_w)[:3]:
        draw.text((pad, y), line, font=hf, fill=INK)
        y += 64
    y += 8
    sum_f = _font(28)
    for line in _wrap(draw, summary, sum_f, content_w)[:3]:
        draw.text((pad, y), line, font=sum_f, fill=DIM)
        y += 38
    y += 28

    # Spec sheet — rows, not cards
    draw.rectangle([pad, y, W - pad, y + 2], fill=RULE)
    y += 28

    rows = [
        ("AFFECTED STACK", stack, TEAL),
        ("CVE / ADVISORY", cve, AMBER),
        ("BLAST RADIUS", blast, sev_color),
        ("SOURCE", f"{tier} · {(vuln.source or '?')[:28]}", INK),
        ("FLEET MATCH", fleet, GREEN if vuln.version_applicable else AMBER),
    ]
    label_f = _font(16, bold=True)
    value_f = _mono(26)
    for lab, val, col in rows:
        draw.text((pad, y), lab, font=label_f, fill=DIM)
        # value may wrap once
        vlines = _wrap(draw, val, value_f, content_w)[:2]
        draw.text((pad, y + 26), vlines[0], font=value_f, fill=col)
        y += 26 + 34
        if len(vlines) > 1:
            draw.text((pad, y), vlines[1], font=value_f, fill=col)
            y += 34
        y += 14

    # Impact — full width text block with accent bar
    y += 8
    impact_top = y
    draw.text((pad + 24, y), "OPERATOR IMPACT", font=_font(18, bold=True), fill=TEAL)
    y += 40
    body = _font(28)
    impact_lines = _wrap(draw, impact, body, content_w - 24)[:6]
    for line in impact_lines:
        draw.text((pad + 24, y), line, font=body, fill=INK)
        y += 38
    draw.rectangle([pad, impact_top, pad + 8, y + 4], fill=TEAL)
    y += 48

    # Footer immediately under content — then crop empty canvas
    draw.rectangle([pad, y, W - pad, y + 2], fill=RULE)
    y += 20
    foot = _font(17)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.text((pad, y), ts, font=foot, fill=DIM)
    bw = draw.textlength("BLACKRAINSENTINEL", font=foot)
    draw.text((W - pad - bw, y), "BLACKRAINSENTINEL", font=foot, fill=TEAL)
    y += 48

    # Crop to content (kill the black void Telegram was showing)
    crop_h = min(H, max(y, 900))
    img = img.crop((0, 0, W, crop_h))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=97, optimize=True, progressive=True, subsampling=0)
    return buf.getvalue()


def render_alert_card_png(vuln: Vulnerability) -> bytes | None:
    """Lossless PNG archive (2× poster)."""
    jpeg = render_alert_card(vuln)
    if not jpeg or Image is None:
        return None
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    big = img.resize((img.width * 2, img.height * 2), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    big.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def build_alert_html(vuln: Vulnerability) -> str:
    """Minimal editable HTML mirror of the poster concept."""
    score = float(vuln.alert_score or 0)
    sev_key = (vuln.severity_tier or "unknown").lower()
    sev_color, sev_label = _SEVERITY.get(sev_key, _SEVERITY["unknown"])
    sev_hex = "#%02x%02x%02x" % sev_color
    headline, summary = _split_title(vuln.title or "")
    if not summary:
        summary = "Confirm exposure on your shared-hosting stack."
    stack = ", ".join(vuln.matched_products[:4]) if vuln.matched_products else "Unmatched"
    cve = ", ".join(vuln.cve_ids[:4]) if vuln.cve_ids else (vuln.external_id or "pre-CVE")
    fleet = "Yes — matches fleet" if vuln.version_applicable else "No — not in fleet versions"
    impact = (vuln.impact_note or "No hosting-specific impact note is available.").strip()
    banner = sev_label
    if vuln.in_kev:
        banner = f"{sev_label}  ·  CISA KEV — ACTIVELY EXPLOITED"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>SentinelWatch Briefing</title>
<style>
  body{{margin:0;background:#080a0e;color:#fafcff;font-family:"Noto Sans",system-ui,sans-serif}}
  .poster{{width:1080px;min-height:1440px;margin:0 auto;padding:0 0 48px;box-sizing:border-box}}
  .strip{{background:{sev_hex};color:#0c080a;text-align:center;font-weight:700;font-size:26px;padding:22px}}
  .pad{{padding:40px 56px}}
  .brand{{color:#00d2be;font-weight:700;letter-spacing:.08em;font-size:22px}}
  .kicker{{color:#8c96a5;font-size:18px;font-weight:700;margin-top:8px}}
  .score{{font-size:140px;font-weight:700;line-height:1;margin:24px 0 0}}
  .cvss{{font-size:56px;font-weight:700}}
  .muted{{color:#8c96a5}}
  h1{{font-size:54px;line-height:1.15;margin:28px 0 12px;font-weight:700}}
  .sum{{font-size:28px;color:#8c96a5;line-height:1.35}}
  .row{{margin:18px 0}}
  .row .l{{font-size:16px;font-weight:700;color:#8c96a5;letter-spacing:.06em}}
  .row .v{{font-size:26px;font-weight:700;margin-top:6px;font-family:ui-monospace,monospace}}
  .impact{{border-left:8px solid #00d2be;padding-left:24px;margin-top:28px}}
  .impact h2{{color:#00d2be;font-size:16px;letter-spacing:.08em}}
  .impact p{{font-size:26px;line-height:1.4}}
  footer{{margin-top:48px;color:#8c96a5;font-size:16px;display:flex;justify-content:space-between}}
</style></head><body>
<article class="poster">
  <div class="strip">{escape(banner)}</div>
  <div class="pad">
    <div class="brand">SENTINELWATCH</div>
    <div class="kicker">HOSTING THREAT BRIEFING</div>
    <div style="display:flex;gap:48px;align-items:flex-end">
      <div>
        <div class="muted" style="font-size:18px;font-weight:700">SENTINEL SCORE</div>
        <div class="score">{score:.0f}</div>
      </div>
      <div>
        <div class="muted" style="font-size:18px;font-weight:700">CVSS</div>
        <div class="cvss">{escape(_fmt_cvss(vuln))}</div>
        <div class="muted" style="font-size:16px">industry · separate</div>
      </div>
    </div>
    <hr style="border:none;height:3px;background:{sev_hex};margin:28px 0"/>
    <h1>{escape(headline)}</h1>
    <p class="sum">{escape(summary)}</p>
    <div class="row"><div class="l">AFFECTED STACK</div><div class="v" style="color:#00d2be">{escape(stack)}</div></div>
    <div class="row"><div class="l">CVE / ADVISORY</div><div class="v" style="color:#ffb428">{escape(cve)}</div></div>
    <div class="row"><div class="l">BLAST RADIUS</div><div class="v" style="color:{sev_hex}">{escape((vuln.blast_radius or 'normal').upper())}</div></div>
    <div class="row"><div class="l">FLEET MATCH</div><div class="v">{escape(fleet)}</div></div>
    <div class="impact"><h2>OPERATOR IMPACT</h2><p>{escape(impact)}</p></div>
    <footer>
      <span>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</span>
      <span style="color:#00d2be;font-weight:700">BLACKRAINSENTINEL</span>
    </footer>
  </div>
</article>
</body></html>
"""


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
    # Same portrait canvas for consistency
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, W, 72], fill=TEAL)
    draw.text((56, 22), "SENTINELWATCH DIGEST", font=_font(26, bold=True), fill=(8, 10, 14))
    draw.text((56, 100), title.upper(), font=_font(22, bold=True), fill=DIM)
    draw.text((56, 140), f"{len(items)} findings", font=_font(48, bold=True), fill=INK)

    y = 220
    for v in items[:8]:
        sev = (v.severity_tier or "unknown").lower()
        color, _ = _SEVERITY.get(sev, _SEVERITY["unknown"])
        draw.rectangle([56, y, 64, y + 100], fill=color)
        draw.text((80, y), f"{float(v.alert_score or 0):.0f}", font=_font(36, bold=True), fill=color)
        for i, line in enumerate(_wrap(draw, v.title or "", _font(24, bold=True), W - 200)[:2]):
            draw.text((200, y + i * 32), line, font=_font(24, bold=True), fill=INK)
        draw.text((200, y + 70), f"{sev} · {_fmt_cvss(v)}", font=_font(18), fill=DIM)
        y += 120

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95, optimize=True, subsampling=0)
    return buf.getvalue()
