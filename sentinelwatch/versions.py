"""
Fleet version applicability.

Operators maintain config/fleet_versions.yaml with products they actually run.
If a finding names affected versions and none overlap the fleet, it is
marked version_applicable=False (still stored; usually digest-only unless KEV).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


_VER_RE = re.compile(
    r"(?P<op>>=|<=|>|<|=|~)?\s*v?(?P<num>\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)


def parse_version(text: str) -> tuple[int, ...] | None:
    m = _VER_RE.search(text or "")
    if not m:
        return None
    parts = [int(p) for p in m.group("num").split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def version_in_range(fleet_ver: str, constraint: str) -> bool:
    """
    Best-effort check whether fleet_ver satisfies a free-text constraint.
    Understands: 8.1, >=8.1, <8.2, 8.1.x, 8.1-8.3, before 8.2, through 4.96
    Unknown shapes → True (fail open for recall).
    """
    fv = parse_version(fleet_ver)
    if fv is None:
        return True
    c = (constraint or "").strip().lower()
    if not c or c in {"*", "all", "any"}:
        return True

    # Range a-b / a – b
    for sep in ("-", "–", " to ", " through "):
        if sep.strip() and sep in c:
            left, _, right = c.partition(sep)
            lv, rv = parse_version(left), parse_version(right)
            if lv and rv:
                return lv <= fv <= rv

    if "before" in c or "prior to" in c or "earlier than" in c:
        rv = parse_version(c)
        return rv is None or fv < rv

    m = _VER_RE.search(c)
    if not m:
        return True
    op = m.group("op") or "="
    tv = parse_version(m.group("num"))
    if tv is None:
        return True
    if op == ">=":
        return fv >= tv
    if op == ">":
        return fv > tv
    if op == "<=":
        return fv <= tv
    if op == "<":
        return fv < tv
    # exact / bare version — compare major.minor.patch
    n = max(len(fv), len(tv))
    fa = fv + (0,) * (n - len(fv))
    ta = tv + (0,) * (n - len(tv))
    return fa[:3] == ta[:3]


def load_fleet_versions(path: Path | str | None) -> dict[str, list[str]]:
    """
    YAML shape:
      php:php: ["8.1", "8.2"]
      exim:exim: ["4.96"]
    """
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out: dict[str, list[str]] = {}
    if not isinstance(data, dict):
        return out
    for key, val in data.items():
        if key.startswith("#"):
            continue
        if isinstance(val, list):
            out[str(key)] = [str(x) for x in val]
        elif isinstance(val, (str, int, float)):
            out[str(key)] = [str(val)]
    return out


def check_applicability(
    matched_product_ids: list[str],
    affected_versions: list[str],
    fleet_versions: dict[str, list[str]],
) -> tuple[bool, bool]:
    """
    Returns (version_applicable, version_unknown).

    - No fleet config for matched products → applicable=True, unknown=True
    - No affected_versions on finding → applicable=True, unknown=True (fail open)
    - Otherwise applicable if any fleet version overlaps any constraint
    """
    if not matched_product_ids:
        return True, True
    if not affected_versions:
        return True, True

    tracked = {
        pid: fleet_versions[pid]
        for pid in matched_product_ids
        if pid in fleet_versions and fleet_versions[pid]
    }
    if not tracked:
        return True, True

    for pid, fleet_list in tracked.items():
        for fv in fleet_list:
            for constraint in affected_versions:
                if version_in_range(fv, constraint):
                    return True, False
    return False, False


def extract_version_hints(text: str) -> list[str]:
    """Pull crude version tokens from advisory text for applicability checks."""
    hints: list[str] = []
    patterns = [
        r"(?:versions?\s+)?(?:before|prior to|earlier than)\s+v?\d+(?:\.\d+){1,3}",
        r"(?:>=|<=|>|<)\s*v?\d+(?:\.\d+){1,3}",
        r"\b\d+\.\d+(?:\.\d+)?(?:\s*[-–]\s*\d+\.\d+(?:\.\d+)?)?\b",
        r"through\s+v?\d+(?:\.\d+){1,3}",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text or "", flags=re.I):
            token = m.group(0).strip()
            if token not in hints:
                hints.append(token)
    return hints[:12]
