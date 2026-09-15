#!/usr/bin/env python3
"""Convert severity GIFs → Telegram-friendly H.264 MP4 (autoplays; large GIFs often freeze)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from imageio_ffmpeg import get_ffmpeg_exe

from sentinelwatch.severity_emblem import SeverityState, assets_dir


def gif_to_mp4(src: Path, dst: Path, *, max_side: int = 720, crf: int = 23) -> Path:
    """Scale longest side to max_side, encode mute H.264 yuv420p for Telegram."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    ffmpeg = get_ffmpeg_exe()
    # even dimensions required for yuv420p
    vf = (
        f"scale='min({max_side},iw)':'min({max_side},ih)':force_original_aspect_ratio=decrease,"
        "scale=trunc(iw/2)*2:trunc(ih/2)*2,fps=12"
    )
    cmd = [
        ffmpeg,
        "-y",
        "-i",
        str(src),
        "-vf",
        vf,
        "-an",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-profile:v",
        "baseline",
        "-level",
        "3.0",
        "-crf",
        str(crf),
        "-movflags",
        "+faststart",
        str(dst),
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    return dst


def main() -> int:
    p = argparse.ArgumentParser(description="Export severity MP4s for Telegram")
    p.add_argument("--dir", type=Path, default=None, help="Asset directory (default: package assets)")
    p.add_argument("--max-side", type=int, default=720)
    args = p.parse_args()
    root = args.dir or assets_dir()
    if not root.is_dir():
        print(f"missing dir: {root}", file=sys.stderr)
        return 1
    for state in SeverityState:
        gif = root / f"{state.value}.gif"
        mp4 = root / f"{state.value}.mp4"
        if not gif.is_file():
            print(f"skip {state.value}: no gif")
            continue
        gif_to_mp4(gif, mp4, max_side=args.max_side)
        print(f"{state.value:10} {gif.stat().st_size/1e6:.1f}MB gif → {mp4.stat().st_size/1e6:.1f}MB mp4")
    return 0


if __name__ == "__main__":
    sys.exit(main())
