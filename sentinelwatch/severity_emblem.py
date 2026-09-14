"""
Severity emblem — branded SW beacon animated by CVSS score band.

GIFs are prerecorded assets. Application code selects the correct file
from CVSS; the GIF itself never fetches or scores vulnerabilities.
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

# Configurable project watermark (embedded in every frame)
PROJECT_NAME = "sentinelwatch"

CANVAS = 512
FPS = 20
DURATION_S = 4.0
FRAME_COUNT = int(FPS * DURATION_S)  # 80


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
    pulse: float  # amplitude 0–1
    spin: float  # revolutions per loop
    expand: float  # ring expand amplitude
    angular: bool  # critical silhouette
    dashed: bool


VISUALS: dict[SeverityState, SeverityVisual] = {
    SeverityState.NONE: SeverityVisual(
        SeverityState.NONE, "NONE", (90, 200, 190), (40, 90, 88), 1, 0.02, 0.15, 0.0, False, False
    ),
    SeverityState.LOW: SeverityVisual(
        SeverityState.LOW, "LOW", (70, 150, 255), (30, 70, 130), 1, 0.04, 0.35, 0.05, False, False
    ),
    SeverityState.MEDIUM: SeverityVisual(
        SeverityState.MEDIUM, "MEDIUM", (240, 180, 40), (120, 90, 20), 2, 0.08, 0.55, 0.18, False, False
    ),
    SeverityState.HIGH: SeverityVisual(
        SeverityState.HIGH, "HIGH", (255, 130, 40), (140, 60, 15), 2, 0.12, 0.85, 0.12, False, False
    ),
    SeverityState.CRITICAL: SeverityVisual(
        SeverityState.CRITICAL, "CRITICAL", (255, 55, 70), (120, 20, 30), 3, 0.18, 1.1, 0.1, True, False
    ),
    SeverityState.UNKNOWN: SeverityVisual(
        SeverityState.UNKNOWN, "UNRATED", (140, 150, 165), (60, 68, 78), 1, 0.0, 0.08, 0.0, False, True
    ),
}


def cvss_to_state(cvss: float | int | str | None) -> SeverityState:
    """Map CVSS v3.1/v4.0 numeric score → severity state (FIRST bands)."""
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


def select_assessment(
    assessments: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Selection policy when multiple CVSS assessments exist:
    prefer NVD/official, then highest score among valid numerics.
    """
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


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    paths = []
    if bold:
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


def render_frame(
    state: SeverityState,
    frame_i: int,
    *,
    project_name: str = PROJECT_NAME,
    score_text: str | None = None,
) -> Image.Image:
    """One 512×512 emblem frame."""
    if Image is None:
        raise RuntimeError("Pillow required")

    vis = VISUALS[state]
    t = frame_i / FRAME_COUNT  # 0..1 loop
    # Smooth pulse (no strobe): sine
    pulse = 1.0 + vis.pulse * math.sin(t * math.pi * 2)
    spin = t * vis.spin * math.pi * 2

    bg = (8, 10, 16)
    img = Image.new("RGB", (CANVAS, CANVAS), bg)
    draw = ImageDraw.Draw(img)
    cx = cy = CANVAS // 2

    # Soft vignette wash toward accent
    for y in range(CANVAS):
        dist = abs(y - cy) / cy
        col = _blend(bg, (vis.accent[0] // 8, vis.accent[1] // 8, vis.accent[2] // 8), 0.35 * (1 - dist))
        draw.line([(0, y), (CANVAS, y)], fill=col)

    # Signal rings
    base_r = 150
    for i in range(vis.ring_count):
        expand = vis.expand * (0.5 + 0.5 * math.sin(t * math.pi * 2 + i))
        r = int((base_r + i * 28) * pulse * (1 + expand * 0.35))
        width = 3 if i == 0 else 2
        if vis.dashed:
            # dashed ring via arcs
            for seg in range(0, 360, 24):
                draw.arc(
                    [cx - r, cy - r, cx + r, cy + r],
                    start=seg + math.degrees(spin * 0.3),
                    end=seg + 12 + math.degrees(spin * 0.3),
                    fill=vis.accent,
                    width=width,
                )
        else:
            draw.ellipse(
                [cx - r, cy - r, cx + r, cy + r],
                outline=_blend(vis.secondary, vis.accent, 0.55 + 0.2 * i),
                width=width,
            )
        # orbital node on outer ring
        if state != SeverityState.NONE and i == vis.ring_count - 1:
            ang = spin * (1 if i % 2 == 0 else -1) + i
            ox = cx + int(r * math.cos(ang))
            oy = cy + int(r * math.sin(ang))
            nr = 6 if state != SeverityState.CRITICAL else 8
            draw.ellipse([ox - nr, oy - nr, ox + nr, oy + nr], fill=vis.accent)

    # Emblem core — hex for critical/high angular identity; circle otherwise
    core_r = int(72 * pulse)
    if vis.angular:
        # angular hex shield
        pts = []
        for k in range(6):
            a = spin * 0.15 + k * math.pi / 3 - math.pi / 6
            pts.append((cx + int(core_r * 1.15 * math.cos(a)), cy + int(core_r * 1.15 * math.sin(a))))
        draw.polygon(pts, fill=(18, 22, 32), outline=vis.accent)
        draw.polygon(pts, outline=vis.accent)
        # inner hex
        pts2 = []
        for k in range(6):
            a = -spin * 0.1 + k * math.pi / 3 - math.pi / 6
            pts2.append((cx + int(core_r * 0.78 * math.cos(a)), cy + int(core_r * 0.78 * math.sin(a))))
        draw.polygon(pts2, outline=_blend(vis.accent, (255, 255, 255), 0.25))
    else:
        draw.ellipse(
            [cx - core_r, cy - core_r, cx + core_r, cy + core_r],
            fill=(18, 22, 32),
            outline=vis.accent,
            width=3,
        )
        draw.ellipse(
            [cx - int(core_r * 0.78), cy - int(core_r * 0.78), cx + int(core_r * 0.78), cy + int(core_r * 0.78)],
            outline=vis.secondary,
            width=2,
        )

    # SW monogram
    mono = _font(42, bold=True)
    label = "SW"
    tw = draw.textlength(label, font=mono)
    draw.text((cx - tw / 2, cy - 28), label, font=mono, fill=vis.accent)

    # Severity text — always readable (shape + color + label)
    sev_f = _font(22, bold=True)
    sev = vis.label
    sw = draw.textlength(sev, font=sev_f)
    draw.text((cx - sw / 2, cy + core_r + 28), sev, font=sev_f, fill=vis.accent)

    if score_text:
        sf = _font(16, bold=True)
        stw = draw.textlength(score_text, font=sf)
        draw.text((cx - stw / 2, cy + core_r + 56), score_text, font=sf, fill=(180, 190, 205))

    # Permanent project watermark
    wm = _font(14, bold=True)
    name = (project_name or PROJECT_NAME).strip().lower()
    ww = draw.textlength(name, font=wm)
    draw.text(((CANVAS - ww) / 2, CANVAS - 36), name, font=wm, fill=(0, 160, 150))

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
    frames = [
        render_frame(state, i, project_name=project_name, score_text=score_text)
        for i in range(FRAME_COUNT)
    ]
    # Quantize for smaller GIFs
    q = [f.convert("P", palette=Image.Palette.ADAPTIVE, colors=64) for f in frames]
    buf = io.BytesIO()
    duration_ms = int(1000 / FPS)
    q[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=q[1:],
        duration=duration_ms,
        loop=0,
        optimize=True,
        disposal=2,
    )
    return buf.getvalue()


def assets_dir() -> Path:
    return Path(__file__).resolve().parent / "assets" / "severity"


def asset_paths(state: SeverityState, *, project_name: str = PROJECT_NAME) -> dict[str, Path]:
    root = assets_dir()
    stem = state.value
    return {
        "gif": root / f"{stem}.gif",
        "png": root / f"{stem}.png",
    }


def resolve_assets(
    cvss: float | int | str | None,
    *,
    project_name: str = PROJECT_NAME,
) -> tuple[SeverityState, Path, Path]:
    """Return (state, gif_path, png_path) for a CVSS score."""
    state = cvss_to_state(cvss)
    paths = asset_paths(state, project_name=project_name)
    return state, paths["gif"], paths["png"]


def export_all(*, project_name: str = PROJECT_NAME, out_dir: Path | None = None) -> dict[str, dict[str, Path]]:
    """Write all six GIFs + PNGs. Reproducible export entrypoint."""
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
