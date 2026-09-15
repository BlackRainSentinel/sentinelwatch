"""
Severity emblem — H2 code-rain live wallpaper animated by CVSS score band.

Creative direction: phosphor-green matrix rain, faded SENTINEL WATCH watermark
under the rain, glass intel plate. Red only on the CRITICAL chip.
GIFs are prerecorded; app code selects the file from CVSS.
"""

from __future__ import annotations

import io
import math
import random
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageFont = None  # type: ignore

PROJECT_NAME = "sentinelwatch"

CANVAS = 640
FPS = 12
DURATION_S = 2.5
FRAME_COUNT = int(FPS * DURATION_S)

BLACK = (4, 8, 6)
PHOS = (0, 255, 120)
PHOS_DIM = (0, 140, 70)
ICE = (230, 245, 235)
DIM = (90, 120, 100)
PANEL = (6, 18, 12)
GLYPHS = "01ABCDEF{}[]<>/;$#"


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
    rain_bright: float
    rain_speed: float
    chip_red: bool


VISUALS: dict[SeverityState, SeverityVisual] = {
    SeverityState.NONE: SeverityVisual(
        SeverityState.NONE, "NONE", (90, 200, 190), (40, 90, 88), 0.55, 0.6, False
    ),
    SeverityState.LOW: SeverityVisual(
        SeverityState.LOW, "LOW", (70, 150, 255), (30, 70, 130), 0.7, 0.85, False
    ),
    SeverityState.MEDIUM: SeverityVisual(
        SeverityState.MEDIUM, "MEDIUM", (240, 180, 40), (120, 90, 20), 0.85, 1.0, False
    ),
    SeverityState.HIGH: SeverityVisual(
        SeverityState.HIGH, "HIGH", (255, 130, 40), (140, 60, 15), 0.95, 1.2, False
    ),
    SeverityState.CRITICAL: SeverityVisual(
        SeverityState.CRITICAL, "CRITICAL", (255, 55, 70), (120, 20, 30), 1.0, 1.45, True
    ),
    SeverityState.UNKNOWN: SeverityVisual(
        SeverityState.UNKNOWN, "UNRATED", (140, 150, 165), (60, 68, 78), 0.45, 0.4, False
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
    if weight == "mono":
        paths += [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
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


def _make_watermark(accent: tuple[int, int, int]) -> Image.Image:
    """Faded SENTINEL / WATCH — sits under matrix rain."""
    wm = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    wd = ImageDraw.Draw(wm)
    f = _font(int(CANVAS * 0.145), weight="condensed")
    y0 = int(CANVAS * 0.045)
    yy = y0
    gap = int(CANVAS * 0.145)
    fill = (*_blend((0, 40, 24), accent, 0.35), 44)
    edge = (*_blend((0, 28, 16), accent, 0.25), 24)
    for line in ("SENTINEL", "WATCH"):
        tw = wd.textlength(line, font=f)
        x = (CANVAS - tw) / 2
        for dx, dy in ((-2, 0), (2, 0), (0, -2), (0, 2)):
            wd.text((x + dx, yy + dy), line, font=f, fill=edge)
        wd.text((x, yy), line, font=f, fill=fill)
        yy += gap

    block_h = yy - y0 + 8
    block = wm.crop((0, y0, CANVAS, y0 + block_h)).copy()
    refl = block.transpose(Image.FLIP_TOP_BOTTOM)
    fade = Image.new("L", refl.size, 0)
    fd = ImageDraw.Draw(fade)
    for y in range(refl.height):
        fd.line(
            [(0, y), (refl.width, y)],
            fill=max(0, int(90 * (1 - y / max(1, refl.height - 1)) ** 1.8)),
        )
    r, g, b, a = refl.split()
    a = Image.composite(
        Image.eval(a, lambda v: int(v * 0.4)),
        Image.new("L", a.size, 0),
        fade,
    )
    refl = Image.merge("RGBA", (r, g, b, a))
    mirror_y = y0 + block_h - int(CANVAS * 0.04)
    wm.paste(refl, (0, mirror_y), refl)
    wd.line(
        [(int(CANVAS * 0.18), mirror_y - 1), (int(CANVAS * 0.82), mirror_y - 1)],
        fill=(*_blend(PHOS_DIM, accent, 0.3), 20),
        width=1,
    )
    return wm.filter(ImageFilter.GaussianBlur(radius=0.8))


def _column_streams(state: SeverityState, cols: int) -> tuple[list[list[str]], list[int], list[int]]:
    streams: list[list[str]] = []
    heads: list[int] = []
    speeds: list[int] = []
    for col in range(cols):
        rng = random.Random(10_000 + hash(state.value) % 10_000 + col)
        streams.append([rng.choice(GLYPHS + "01" * 4) for _ in range(64)])
        heads.append(rng.randint(0, 40))
        speeds.append(1 if col % 3 else 2)
    return streams, heads, speeds


def _draw_rain(
    draw: ImageDraw.ImageDraw,
    *,
    frame_i: int,
    vis: SeverityVisual,
    streams: list[list[str]],
    heads: list[int],
    speeds: list[int],
) -> None:
    cols = len(streams)
    mono = _font(max(11, CANVAS // 48), weight="mono")
    col_w = CANVAS // cols
    rows = 42
    row_h = max(14, CANVAS // rows)
    rain = _blend(BLACK, PHOS, 0.55 + 0.35 * vis.rain_bright)
    for col in range(cols):
        x = 4 + col * col_w
        step = max(1, int(round(speeds[col] * vis.rain_speed)))
        head = (heads[col] + frame_i * step) % 48
        for row in range(rows):
            y = 2 + row * row_h
            ch = streams[col][(row + frame_i * step) % len(streams[col])]
            dist = (row - head) % 48
            if dist == 0:
                colr = ICE
            elif dist < 4:
                colr = _blend(BLACK, rain, 0.9 - dist * 0.15)
            else:
                bright = (0.06 + 0.42 * ((row + col) % 7) / 7) * vis.rain_bright
                colr = _blend(BLACK, rain, bright)
            draw.text((x, y), ch, font=mono, fill=colr)


def _draw_intel_card(
    draw: ImageDraw.ImageDraw,
    vis: SeverityVisual,
    *,
    score_text: str | None,
) -> None:
    m = int(CANVAS * 0.11)
    top = int(CANVAS * 0.55)
    bot = int(CANVAS * 0.92)
    border = PHOS
    draw.rounded_rectangle([m, top, CANVAS - m, bot], 16, fill=PANEL, outline=border, width=2)

    x0 = m + int(CANVAS * 0.04)
    label_f = _font(max(12, CANVAS // 42), weight="bold")
    title_f = _font(max(18, CANVAS // 26), weight="black")
    sub_f = _font(max(13, CANVAS // 38), weight="regular")
    tiny_f = _font(max(10, CANVAS // 55), weight="bold")
    mono_f = _font(max(13, CANVAS // 34), weight="mono")
    crit_f = _font(max(12, CANVAS // 40), weight="bold")

    draw.text((x0, top + int(CANVAS * 0.028)), "LIVE THREAT STREAM", font=label_f, fill=PHOS_DIM)
    draw.text((x0, top + int(CANVAS * 0.075)), f"{vis.label} advisory", font=title_f, fill=ICE)
    draw.text((x0, top + int(CANVAS * 0.14)), "Shared-hosting perimeter", font=sub_f, fill=DIM)

    y_line = top + int(CANVAS * 0.195)
    draw.line([(x0, y_line), (CANVAS - m - int(CANVAS * 0.04), y_line)], fill=PHOS_DIM, width=2)

    score = score_text or "CVSS —"
    fields = [
        ("BAND", vis.label),
        ("SCORE", score.replace("CVSS ", "") if score.startswith("CVSS ") else score),
        ("STACK", "shared-host"),
        ("WATCH", "active"),
    ]
    for i, (lab, val) in enumerate(fields):
        x = x0 + (i % 2) * int(CANVAS * 0.38)
        y = y_line + int(CANVAS * 0.03) + (i // 2) * int(CANVAS * 0.08)
        draw.text((x, y), lab, font=tiny_f, fill=DIM)
        # Amber for CVSS score (H2); red reserved for CRITICAL chip only
        val_col = (240, 190, 50) if i == 1 else PHOS
        draw.text((x, y + int(CANVAS * 0.028)), val, font=mono_f, fill=val_col)

    chip_col = (220, 55, 70) if vis.chip_red else vis.accent
    cx = CANVAS // 2
    cy = bot - int(CANVAS * 0.05)
    half_w = int(CANVAS * 0.11)
    draw.rounded_rectangle(
        [cx - half_w, cy - int(CANVAS * 0.022), cx + half_w, cy + int(CANVAS * 0.022)],
        8,
        outline=chip_col,
        width=2,
    )
    tw = draw.textlength(vis.label, font=crit_f)
    draw.text((cx - tw / 2, cy - int(CANVAS * 0.015)), vis.label, font=crit_f, fill=chip_col)


def render_frame(
    state: SeverityState,
    frame_i: int,
    *,
    project_name: str = PROJECT_NAME,
    score_text: str | None = None,
    _wm_cache: dict[SeverityState, Image.Image] | None = None,
    _rain_cache: dict[SeverityState, tuple] | None = None,
) -> Image.Image:
    if Image is None:
        raise RuntimeError("Pillow required")

    vis = VISUALS[state]
    img = Image.new("RGB", (CANVAS, CANVAS), BLACK)
    draw = ImageDraw.Draw(img)

    # 1) Faded brand watermark UNDER the matrix
    cache = _wm_cache if _wm_cache is not None else {}
    if state not in cache:
        # Brand stays phosphor-tinted; severity only tints chip/score
        cache[state] = _make_watermark(PHOS if state != SeverityState.UNKNOWN else vis.accent)
    img = Image.alpha_composite(img.convert("RGBA"), cache[state]).convert("RGB")
    draw = ImageDraw.Draw(img)

    # 2) Matrix rain ON TOP of watermark
    rain_cache = _rain_cache if _rain_cache is not None else {}
    if state not in rain_cache:
        rain_cache[state] = _column_streams(state, cols=28)
    streams, heads, speeds = rain_cache[state]
    _draw_rain(draw, frame_i=frame_i, vis=vis, streams=streams, heads=heads, speeds=speeds)

    # 3) Glass intel plate
    _draw_intel_card(draw, vis, score_text=score_text)

    # project_name reserved for future custom brand lines (watermark is fixed SENTINEL WATCH)
    _ = project_name
    return img


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
    wm_cache: dict[SeverityState, Image.Image] = {}
    rain_cache: dict[SeverityState, tuple] = {}
    frames = [
        render_frame(
            state,
            i,
            project_name=project_name,
            score_text=score_text,
            _wm_cache=wm_cache,
            _rain_cache=rain_cache,
        )
        for i in range(FRAME_COUNT)
    ]
    pal = frames[0].quantize(colors=160, method=Image.Quantize.MEDIANCUT)
    q = [frames[0].quantize(palette=pal)] + [f.quantize(palette=pal) for f in frames[1:]]
    buf = io.BytesIO()
    q[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=q[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=False,
        disposal=2,
    )
    return buf.getvalue()


def assets_dir() -> Path:
    return Path(__file__).resolve().parent / "assets" / "severity"


def asset_paths(state: SeverityState, *, project_name: str = PROJECT_NAME) -> dict[str, Path]:
    root = assets_dir()
    _ = project_name
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
