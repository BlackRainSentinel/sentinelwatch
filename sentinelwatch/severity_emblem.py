"""
Severity emblem — cinematic SW Beacon animated by CVSS score band.

Creative direction: cyber-neon HUD + giant cinematic background typography
(poster watermark), scan beams, hex lattice, multi-node orbits.
GIFs are prerecorded; app code selects the file from CVSS.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFont = None  # type: ignore

PROJECT_NAME = "sentinelwatch"

CANVAS = 512
FPS = 20
DURATION_S = 4.0
FRAME_COUNT = int(FPS * DURATION_S)


class SeverityState(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SeverityVisual:
    state: SeverityState
    label: str
    accent: tuple[int, int, int]
    secondary: tuple[int, int, int]
    ring_count: int
    pulse: float
    spin: float
    expand: float
    angular: bool
    dashed: bool


VISUALS: dict[SeverityState, SeverityVisual] = {
    SeverityState.NONE: SeverityVisual(
        SeverityState.NONE, "NONE", (90, 200, 190), (40, 90, 88), 1, 0.03, 0.2, 0.0, False, False
    ),
    SeverityState.LOW: SeverityVisual(
        SeverityState.LOW, "LOW", (70, 150, 255), (30, 70, 130), 1, 0.05, 0.4, 0.06, False, False
    ),
    SeverityState.MEDIUM: SeverityVisual(
        SeverityState.MEDIUM, "MEDIUM", (240, 180, 40), (120, 90, 20), 2, 0.09, 0.6, 0.2, False, False
    ),
    SeverityState.HIGH: SeverityVisual(
        SeverityState.HIGH, "HIGH", (255, 130, 40), (140, 60, 15), 2, 0.13, 0.95, 0.14, False, False
    ),
    SeverityState.CRITICAL: SeverityVisual(
        SeverityState.CRITICAL, "CRITICAL", (255, 55, 70), (120, 20, 30), 3, 0.2, 1.15, 0.12, True, False
    ),
    SeverityState.UNKNOWN: SeverityVisual(
        SeverityState.UNKNOWN, "UNRATED", (140, 150, 165), (60, 68, 78), 1, 0.0, 0.1, 0.0, False, True
    ),
}


def cvss_to_state(cvss: float | int | str | None) -> SeverityState:
    if cvss is None or cvss == "":
        return SeverityState.UNKNOWN
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return SeverityState.UNKNOWN
    if math.isnan(score) or math.isinf(score) or score < 0 or score > 10:
        return SeverityState.UNKNOWN
    if score == 0.0:
        return SeverityState.NONE
    if score <= 3.9:
        return SeverityState.LOW
    if score <= 6.9:
        return SeverityState.MEDIUM
    if score <= 8.9:
        return SeverityState.HIGH
    return SeverityState.CRITICAL


def select_assessment(assessments: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not assessments:
        return None

    def key(a: dict[str, Any]) -> tuple:
        src = str(a.get("source", "")).lower()
        official = 0 if src in {"nvd", "official", "first", "cna"} else 1
        try:
            s = float(a["score"])
            valid = 0 if 0 <= s <= 10 else 1
            score_sort = -s if valid == 0 else 0
        except (KeyError, TypeError, ValueError):
            valid, score_sort = 1, 0
        return (valid, official, score_sort)

    return sorted(assessments, key=key)[0]


def _font(size: int, *, weight: str = "regular") -> ImageFont.ImageFont:
    paths: list[str] = []
    if weight == "black":
        paths += [
            "/usr/share/fonts/truetype/noto/NotoSansDisplay-Black.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Black.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-ExtraBold.ttf",
        ]
    if weight in {"extrabold", "black", "condensed"}:
        paths += [
            "/usr/share/fonts/truetype/noto/NotoSans-ExtraCondensedExtraBold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-CondensedExtraBold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-ExtraBold.ttf",
        ]
    if weight in {"bold", "extrabold", "black", "condensed"}:
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


def _blend(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        int(a[0] + (b[0] - a[0]) * t),
        int(a[1] + (b[1] - a[1]) * t),
        int(a[2] + (b[2] - a[2]) * t),
    )


def _draw_hex_grid(draw: ImageDraw.ImageDraw, accent: tuple[int, int, int], t: float) -> None:
    size = 28
    h = size * math.sqrt(3)
    col = _blend((8, 10, 16), accent, 0.14 + 0.05 * math.sin(t * math.pi * 2))
    for row in range(-1, 22):
        for col_i in range(-1, 22):
            x = col_i * size * 1.5
            y = row * h + (col_i % 2) * (h / 2)
            pts = [
                (x + size * 0.42 * math.cos(math.pi / 6 + k * math.pi / 3),
                 y + size * 0.42 * math.sin(math.pi / 6 + k * math.pi / 3))
                for k in range(6)
            ]
            draw.polygon(pts, outline=col)


def _draw_giant_watermark(
    draw: ImageDraw.ImageDraw,
    name: str,
    accent: tuple[int, int, int],
    t: float,
) -> None:
    """Huge condensed poster type — brand as atmosphere, not a footer stamp."""
    name = (name or PROJECT_NAME).strip().lower()
    lines = ["SENTINEL", "WATCH"] if name == "sentinelwatch" else [name.upper()]
    font = _font(122 if len(lines) > 1 else 100, weight="condensed")
    drift = int(10 * math.sin(t * math.pi * 2))
    fill = _blend((14, 16, 22), accent, 0.28)
    edge = _blend((20, 24, 32), accent, 0.42)

    for i, line in enumerate(lines):
        tw = draw.textlength(line, font=font)
        x = (CANVAS - tw) / 2
        y = 55 + drift + i * 115
        for dx, dy in ((-2, 0), (2, 0), (0, -2), (0, 2)):
            draw.text((x + dx, y + dy), line, font=font, fill=edge)
        draw.text((x, y), line, font=font, fill=fill)

    # Marquee strip — keeps motion alive at the edge
    micro = _font(20, weight="condensed")
    strip = f"  {name}  ·  " * 10
    sx = -int((t * 220) % 240)
    draw.text((sx, CANVAS - 20), strip, font=micro, fill=_blend((12, 14, 20), accent, 0.35))


def _hud_brackets(draw: ImageDraw.ImageDraw, color: tuple[int, int, int], inset: int = 22) -> None:
    arm, w = 40, 3
    draw.line([(inset, inset + arm), (inset, inset), (inset + arm, inset)], fill=color, width=w)
    draw.line(
        [(CANVAS - inset - arm, inset), (CANVAS - inset, inset), (CANVAS - inset, inset + arm)],
        fill=color,
        width=w,
    )
    draw.line(
        [(inset, CANVAS - inset - arm), (inset, CANVAS - inset), (inset + arm, CANVAS - inset)],
        fill=color,
        width=w,
    )
    draw.line(
        [
            (CANVAS - inset - arm, CANVAS - inset),
            (CANVAS - inset, CANVAS - inset),
            (CANVAS - inset, CANVAS - inset - arm),
        ],
        fill=color,
        width=w,
    )


def _scan_beam(base: Image.Image, accent: tuple[int, int, int], t: float, intensity: float) -> Image.Image:
    if intensity <= 0.01:
        return base
    overlay = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    pos = t % 1.0
    for i in range(-20, 21, 3):
        alpha = int(max(0, 60 * intensity - abs(i) * 2.4))
        if alpha < 4:
            continue
        x0 = -90 + pos * (CANVAS + 180) + i
        od.line([(x0, -30), (x0 + CANVAS * 0.38, CANVAS + 30)], fill=(*accent, alpha), width=4)
    x0 = -90 + pos * (CANVAS + 180)
    od.line(
        [(x0, -30), (x0 + CANVAS * 0.38, CANVAS + 30)],
        fill=(*accent, int(150 * intensity)),
        width=2,
    )
    return Image.alpha_composite(base.convert("RGBA"), overlay).convert("RGB")


def _particles(
    draw: ImageDraw.ImageDraw,
    accent: tuple[int, int, int],
    t: float,
    count: int,
    spin: float,
) -> None:
    for i in range(count):
        ang = spin * 0.7 + i * (math.pi * 2 / count) + math.sin(t * math.pi * 2 + i) * 0.25
        rad = 90 + (i % 5) * 30 + 12 * math.sin(t * math.pi * 2 + i * 0.6)
        x = CANVAS / 2 + rad * math.cos(ang)
        y = CANVAS / 2 + rad * math.sin(ang)
        r = 2 + (i % 3)
        draw.ellipse([x - r, y - r, x + r, y + r], fill=_blend(accent, (255, 255, 255), 0.2))


def render_frame(
    state: SeverityState,
    frame_i: int,
    *,
    project_name: str = PROJECT_NAME,
    score_text: str | None = None,
) -> Image.Image:
    if Image is None:
        raise RuntimeError("Pillow required")

    vis = VISUALS[state]
    t = frame_i / FRAME_COUNT
    pulse = 1.0 + vis.pulse * math.sin(t * math.pi * 2)
    spin = t * vis.spin * math.pi * 2
    scan_intensity = {
        SeverityState.NONE: 0.2,
        SeverityState.LOW: 0.4,
        SeverityState.MEDIUM: 0.6,
        SeverityState.HIGH: 0.8,
        SeverityState.CRITICAL: 1.0,
        SeverityState.UNKNOWN: 0.25,
    }[state]

    bg = (5, 7, 11)
    img = Image.new("RGB", (CANVAS, CANVAS), bg)
    draw = ImageDraw.Draw(img)
    cx = cy = CANVAS // 2

    for y in range(CANVAS):
        dist = abs(y - cy) / max(cy, 1)
        heat = (vis.accent[0] // 5, vis.accent[1] // 5, vis.accent[2] // 5)
        col = _blend(bg, heat, 0.5 * (1 - dist) + 0.1 * math.sin(t * math.pi * 2))
        draw.line([(0, y), (CANVAS, y)], fill=col)

    _draw_hex_grid(draw, vis.accent, t)
    _draw_giant_watermark(draw, project_name, vis.accent, t)
    _hud_brackets(draw, _blend(vis.secondary, vis.accent, 0.75))

    if vis.expand > 0:
        wave = (t * 1.4) % 1.0
        wr = int(55 + wave * 210)
        wcol = _blend(bg, vis.accent, max(0.05, 0.55 * (1 - wave)))
        draw.ellipse([cx - wr, cy - wr, cx + wr, cy + wr], outline=wcol, width=3)

    base_r = 112
    for i in range(vis.ring_count):
        expand = vis.expand * (0.5 + 0.5 * math.sin(t * math.pi * 2 + i * 1.3))
        r = int((base_r + i * 34) * pulse * (1 + expand * 0.45))
        width = 4 if i == 0 else 2
        ring_col = _blend(vis.secondary, vis.accent, 0.55 + 0.2 * i)
        if vis.dashed:
            for seg in range(0, 360, 18):
                draw.arc(
                    [cx - r, cy - r, cx + r, cy + r],
                    start=seg + math.degrees(spin * 0.45),
                    end=seg + 9 + math.degrees(spin * 0.45),
                    fill=ring_col,
                    width=width,
                )
        else:
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=vis.secondary, width=width + 2)
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=ring_col, width=width)

        if state not in {SeverityState.NONE, SeverityState.UNKNOWN}:
            nodes = 1 + i
            for n in range(nodes):
                ang = spin * (1 if i % 2 == 0 else -1.2) + n * (math.pi * 2 / nodes) + i
                ox = cx + r * math.cos(ang)
                oy = cy + r * math.sin(ang)
                nr = 5 + (2 if state == SeverityState.CRITICAL else 0)
                draw.ellipse([ox - nr, oy - nr, ox + nr, oy + nr], fill=vis.accent)
                draw.ellipse([ox - 2, oy - 2, ox + 2, oy + 2], fill=(255, 255, 255))

    pcount = {
        SeverityState.NONE: 8,
        SeverityState.LOW: 12,
        SeverityState.MEDIUM: 16,
        SeverityState.HIGH: 20,
        SeverityState.CRITICAL: 28,
        SeverityState.UNKNOWN: 8,
    }[state]
    _particles(draw, vis.accent, t, pcount, spin)

    core_r = int(66 * pulse)
    core_fill = (12, 16, 26)
    if vis.angular:
        pts = [
            (cx + int(core_r * 1.22 * math.cos(spin * 0.12 + k * math.pi / 3 - math.pi / 6)),
             cy + int(core_r * 1.22 * math.sin(spin * 0.12 + k * math.pi / 3 - math.pi / 6)))
            for k in range(6)
        ]
        draw.polygon(pts, fill=core_fill, outline=vis.accent)
        pts2 = [
            (cx + int(core_r * 0.7 * math.cos(-spin * 0.08 + k * math.pi / 3 - math.pi / 6)),
             cy + int(core_r * 0.7 * math.sin(-spin * 0.08 + k * math.pi / 3 - math.pi / 6)))
            for k in range(6)
        ]
        draw.polygon(pts2, outline=_blend(vis.accent, (255, 255, 255), 0.35))
        for k in range(6):
            a = spin * 0.12 + k * math.pi / 3 - math.pi / 6
            draw.line(
                [
                    (cx + int(core_r * 1.3 * math.cos(a)), cy + int(core_r * 1.3 * math.sin(a))),
                    (cx + int(core_r * 1.48 * math.cos(a)), cy + int(core_r * 1.48 * math.sin(a))),
                ],
                fill=vis.accent,
                width=3,
            )
    else:
        draw.ellipse(
            [cx - core_r - 5, cy - core_r - 5, cx + core_r + 5, cy + core_r + 5],
            outline=vis.secondary,
            width=2,
        )
        draw.ellipse(
            [cx - core_r, cy - core_r, cx + core_r, cy + core_r],
            fill=core_fill,
            outline=vis.accent,
            width=4,
        )
        draw.ellipse(
            [cx - int(core_r * 0.7), cy - int(core_r * 0.7), cx + int(core_r * 0.7), cy + int(core_r * 0.7)],
            outline=vis.secondary,
            width=2,
        )

    mono = _font(50, weight="black")
    glitch = int(2 * math.sin(t * math.pi * 8)) if state == SeverityState.CRITICAL else 0
    tw = draw.textlength("SW", font=mono)
    draw.text((cx - tw / 2 + glitch, cy - 34), "SW", font=mono, fill=vis.accent)
    if glitch:
        draw.text(
            (cx - tw / 2 - glitch, cy - 34),
            "SW",
            font=mono,
            fill=_blend(vis.accent, (255, 90, 110), 0.45),
        )

    sev_f = _font(28, weight="extrabold")
    sev = vis.label
    sw = draw.textlength(sev, font=sev_f)
    plate_y = cy + core_r + 34
    draw.rounded_rectangle(
        [cx - sw / 2 - 20, plate_y - 8, cx + sw / 2 + 20, plate_y + 36],
        radius=12,
        fill=(8, 10, 16),
        outline=vis.accent,
        width=2,
    )
    draw.text((cx - sw / 2, plate_y), sev, font=sev_f, fill=vis.accent)

    if score_text:
        sf = _font(15, weight="bold")
        stw = draw.textlength(score_text, font=sf)
        draw.text((cx - stw / 2, plate_y + 44), score_text, font=sf, fill=(168, 180, 196))

    return _scan_beam(img, vis.accent, t, scan_intensity)


def render_static_png(
    state: SeverityState,
    *,
    project_name: str = PROJECT_NAME,
    score_text: str | None = None,
) -> bytes:
    img = render_frame(state, 0, project_name=project_name, score_text=score_text)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def render_gif(
    state: SeverityState,
    *,
    project_name: str = PROJECT_NAME,
    score_text: str | None = None,
) -> bytes:
    frames = [
        render_frame(state, i, project_name=project_name, score_text=score_text)
        for i in range(FRAME_COUNT)
    ]
    q = [f.convert("P", palette=Image.Palette.ADAPTIVE, colors=96) for f in frames]
    buf = io.BytesIO()
    q[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=q[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=True,
        disposal=2,
    )
    return buf.getvalue()


def assets_dir() -> Path:
    return Path(__file__).resolve().parent / "assets" / "severity"


def asset_paths(state: SeverityState, *, project_name: str = PROJECT_NAME) -> dict[str, Path]:
    root = assets_dir()
    return {"gif": root / f"{state.value}.gif", "png": root / f"{state.value}.png"}


def resolve_assets(
    cvss: float | int | str | None,
    *,
    project_name: str = PROJECT_NAME,
) -> tuple[SeverityState, Path, Path]:
    state = cvss_to_state(cvss)
    paths = asset_paths(state, project_name=project_name)
    return state, paths["gif"], paths["png"]


def export_all(*, project_name: str = PROJECT_NAME, out_dir: Path | None = None) -> dict[str, dict[str, Path]]:
    root = out_dir or assets_dir()
    root.mkdir(parents=True, exist_ok=True)
    written: dict[str, dict[str, Path]] = {}
    score_hints = {
        SeverityState.NONE: "CVSS 0.0",
        SeverityState.LOW: "CVSS 0.1–3.9",
        SeverityState.MEDIUM: "CVSS 4.0–6.9",
        SeverityState.HIGH: "CVSS 7.0–8.9",
        SeverityState.CRITICAL: "CVSS 9.0–10.0",
        SeverityState.UNKNOWN: "CVSS —",
    }
    for state in SeverityState:
        gif_path = root / f"{state.value}.gif"
        png_path = root / f"{state.value}.png"
        hint = score_hints[state]
        gif_path.write_bytes(render_gif(state, project_name=project_name, score_text=hint))
        png_path.write_bytes(render_static_png(state, project_name=project_name, score_text=hint))
        written[state.value] = {"gif": gif_path, "png": png_path}
    return written
