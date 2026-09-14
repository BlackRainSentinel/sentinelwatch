#!/usr/bin/env python3
"""Reproducible export: six severity GIFs + PNG fallbacks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinelwatch.severity_emblem import PROJECT_NAME, export_all


def main() -> int:
    p = argparse.ArgumentParser(description="Export SentinelWatch severity emblem assets")
    p.add_argument("--project-name", default=PROJECT_NAME)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()
    written = export_all(project_name=args.project_name, out_dir=args.out)
    for state, paths in written.items():
        for kind, path in paths.items():
            print(f"{state:10} {kind:3}  {path.stat().st_size:8} B  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
