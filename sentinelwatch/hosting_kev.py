"""Load curated hosting-actively-abused CVE extras (community/hosting KEV)."""

from __future__ import annotations

from pathlib import Path

import yaml


def load_hosting_kev(path: Path | str | None) -> set[str]:
    if path is None:
        return set()
    p = Path(path)
    if not p.is_file():
        return set()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cves: set[str] = set()
    if isinstance(data, dict):
        items = data.get("cves") or data.get("hosting_kev") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []
    for item in items:
        if isinstance(item, str):
            cves.add(item.upper().strip())
        elif isinstance(item, dict) and item.get("cve"):
            cves.add(str(item["cve"]).upper().strip())
    return {c for c in cves if c.startswith("CVE-")}
