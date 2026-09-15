#!/usr/bin/env python3
"""Procedural H2 export (overwrites threat-core pack GIFs — use with care).

Prefer: python scripts/install_threat_core_gifs.py ~/Downloads/threat-core-6-high-quality-gifs.zip
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinelwatch.severity_emblem import PROJECT_NAME, export_all


def main() -> int:
    p = argparse.ArgumentParser(description="Export procedural H2 severity emblem assets")
    p.add_argument("--project-name", default=PROJECT_NAME)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument(
        "--force",
        action="store_true",
        help="Required to overwrite sentinelwatch/assets/severity (threat-core pack lives there)",
    )
    args = p.parse_args()
    out = args.out
    if out is None and not args.force:
        print(
            "Refusing to overwrite production threat-core GIFs.\n"
            "Use: python scripts/install_threat_core_gifs.py <zip>\n"
            "Or pass --force to regenerate the procedural H2 look.",
            file=sys.stderr,
        )
        return 2
    written = export_all(project_name=args.project_name, out_dir=out)
    for state, paths in written.items():
        for kind, path in paths.items():
            print(f"{state:10} {kind:3}  {path.stat().st_size:8} B  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
