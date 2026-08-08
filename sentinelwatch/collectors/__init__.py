"""Build collector instances from YAML config. Add a source = add config (or a new module)."""

from __future__ import annotations

import logging
from typing import Any

from sentinelwatch.collectors.base import Collector
from sentinelwatch.collectors.feed import FeedCollector
from sentinelwatch.collectors.github_advisories import GithubAdvisoriesCollector
from sentinelwatch.collectors.nvd import NvdCollector
from sentinelwatch.collectors.wordfence import DEFAULT_URL as WORDFENCE_URL
from sentinelwatch.collectors.wordfence import WordfenceCollector

log = logging.getLogger(__name__)


def build_collectors(config: dict[str, Any]) -> list[Collector]:
    """
    Instantiate enabled collectors from config['sources'].

    Each entry:
      - name: unique source id
      - type: feed | nvd | wordfence | github_advisories
      - enabled: bool (default true)
      - …type-specific options
    """
    sources = config.get("sources") or []
    collectors: list[Collector] = []

    for entry in sources:
        if not isinstance(entry, dict):
            log.warning("Skipping malformed source entry: %r", entry)
            continue
        if entry.get("enabled", True) is False:
            continue

        source_type = (entry.get("type") or "").strip().lower()
        name = (entry.get("name") or source_type or "unnamed").strip()

        try:
            collector = _build_one(source_type, name, entry)
        except Exception:
            log.exception("Failed to build collector %r (type=%r)", name, source_type)
            continue

        if collector is None:
            log.warning("Unknown collector type %r for source %r", source_type, name)
            continue
        collectors.append(collector)

    return collectors


def _build_one(source_type: str, name: str, entry: dict[str, Any]) -> Collector | None:
    opts = {k: v for k, v in entry.items() if k not in {"type", "enabled"}}

    if source_type == "feed":
        url = opts.get("url")
        if not url:
            raise ValueError(f"feed source {name!r} requires url")
        return FeedCollector(
            source=name,
            url=url,
            include_keywords=opts.get("include_keywords"),
            exclude_keywords=opts.get("exclude_keywords"),
            default_products=opts.get("default_products"),
            max_entries=int(opts.get("max_entries", 100)),
        )

    if source_type == "nvd":
        return NvdCollector(
            keywords=list(opts.get("keywords") or []),
            lookback_days=int(opts.get("lookback_days", 14)),
            results_per_page=int(opts.get("results_per_page", 50)),
            sleep_seconds=opts.get("sleep_seconds"),
        )

    if source_type == "wordfence":
        return WordfenceCollector(
            url=opts.get("url") or WORDFENCE_URL,
            max_items=int(opts.get("max_items", 200)),
        )

    if source_type == "github_advisories":
        return GithubAdvisoriesCollector(
            ecosystems=opts.get("ecosystems"),
            per_page=int(opts.get("per_page", 50)),
            max_pages=int(opts.get("max_pages", 2)),
        )

    return None
