#!/usr/bin/env python3
"""Install threat-core severity GIFs into sentinelwatch/assets/severity/.

Maps pack filenames → CVSS states:
  none / low / medium / high / critical / unscored → unknown
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from PIL import Image

from sentinelwatch.severity_emblem import assets_dir

PACK_MAP = {
    "none.gif": "none.gif",
    "low.gif": "low.gif",
    "medium.gif": "medium.gif",
    "high.gif": "high.gif",
    "critical.gif": "critical.gif",
    "unscored.gif": "unknown.gif",
}


def install_from_zip(zip_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(zip_path) as zf:
        names = {Path(n).name: n for n in zf.namelist() if not n.endswith("/")}
        missing = [k for k in PACK_MAP if k not in names]
        if missing:
            raise SystemExit(f"ZIP missing required files: {missing}")
        for pack_name, dest_name in PACK_MAP.items():
            data = zf.read(names[pack_name])
            gif_path = out_dir / dest_name
            gif_path.write_bytes(data)
            # PNG fallback = first frame
            from io import BytesIO

            im = Image.open(BytesIO(data))
            im.seek(0)
            png_path = out_dir / dest_name.replace(".gif", ".png")
            im.convert("RGBA").save(png_path, format="PNG", optimize=True)
            written.extend([gif_path, png_path])
            print(f"{dest_name:12} {gif_path.stat().st_size / 1e6:.1f}MB  png={png_path.stat().st_size // 1024}KB")
    return written


def main() -> int:
    p = argparse.ArgumentParser(description="Install threat-core severity GIFs")
    p.add_argument(
        "zip_path",
        type=Path,
        nargs="?",
        default=Path.home() / "Downloads" / "threat-core-6-high-quality-gifs.zip",
    )
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()
    if not args.zip_path.is_file():
        print(f"ZIP not found: {args.zip_path}", file=sys.stderr)
        return 1
    install_from_zip(args.zip_path, args.out or assets_dir())
    return 0


if __name__ == "__main__":
    sys.exit(main())
