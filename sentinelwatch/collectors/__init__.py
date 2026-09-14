"""Build collector instances from YAML config."""

from __future__ import annotations

import logging
from typing import Any

from sentinelwatch.collectors.base import Collector
from sentinelwatch.collectors.changelog import (
    ChangelogCollector,
    bind_collector,
    csf_collector,
    directadmin_collector,
    jetbackup_collector,
    pureftpd_collector,
)
from sentinelwatch.collectors.feed import FeedCollector
from sentinelwatch.collectors.github_advisories import GithubAdvisoriesCollector
from sentinelwatch.collectors.html_advisories import HtmlAdvisoriesCollector
from sentinelwatch.collectors.kev import KevCollector
from sentinelwatch.collectors.nvd import NvdCollector
from sentinelwatch.collectors.wordfence import DEFAULT_URL as WORDFENCE_URL
from sentinelwatch.collectors.wordfence import WordfenceCollector
from sentinelwatch.taxonomy import PRODUCTS

log = logging.getLogger(__name__)

_CHANGELOG_FACTORIES = {
    "directadmin": directadmin_collector,
    "csf": csf_collector,
    "pureftpd": pureftpd_collector,
    "jetbackup": jetbackup_collector,
    "bind": bind_collector,
    "isc_bind": bind_collector,
}


def build_collectors(
    config: dict[str, Any],
    *,
    schedule: str | None = None,
) -> list[Collector]:
    """
    Build enabled collectors. If schedule is 'fast' or 'slow', filter by
    collector.schedule (tier3/wordfence default slow).
    """
    sources = config.get("sources") or []
    collectors: list[Collector] = []

    for entry in sources:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        source_type = (entry.get("type") or "").strip().lower()
        name = (entry.get("name") or source_type or "unnamed").strip()
        try:
            collector = _build_one(source_type, name, entry, config)
        except Exception:
            log.exception("Failed to build collector %r", name)
            continue
        if collector is None:
            log.warning("Unknown collector type %r for %r", source_type, name)
            continue
        # Allow YAML override of schedule class
        if entry.get("schedule"):
            collector.schedule = str(entry["schedule"])
        if schedule and getattr(collector, "schedule", "fast") != schedule:
            continue
        collectors.append(collector)
    return collectors


def _build_one(
    source_type: str, name: str, entry: dict[str, Any], config: dict[str, Any]
) -> Collector | None:
    opts = {k: v for k, v in entry.items() if k not in {"type", "enabled", "schedule"}}
    tier = int(opts.get("source_tier") or opts.get("tier") or _default_tier(source_type))

    if source_type == "feed":
        url = opts.get("url")
        if not url:
            raise ValueError(f"feed {name!r} requires url")
        c = FeedCollector(
            source=name,
            url=url,
            source_tier=tier,
            include_keywords=opts.get("include_keywords"),
            exclude_keywords=opts.get("exclude_keywords"),
            default_products=opts.get("default_products"),
            max_entries=int(opts.get("max_entries", 100)),
        )
        c.schedule = "fast" if tier <= 2 else "slow"
        return c

    if source_type == "nvd":
        return NvdCollector(
            keywords=list(opts.get("keywords") or []),
            lookback_days=int(opts.get("lookback_days", 14)),
            results_per_page=int(opts.get("results_per_page", 50)),
            sleep_seconds=opts.get("sleep_seconds"),
            source_tier=tier,
            use_cpe=bool(opts.get("use_cpe", True)),
            taxonomy=list(PRODUCTS),
        )

    if source_type == "wordfence":
        c = WordfenceCollector(
            url=opts.get("url") or WORDFENCE_URL,
            max_items=int(opts.get("max_items", 200)),
            source_tier=tier,
        )
        c.schedule = "slow"
        return c

    if source_type == "github_advisories":
        return GithubAdvisoriesCollector(
            ecosystems=opts.get("ecosystems"),
            include_keywords=opts.get("include_keywords"),
            per_page=int(opts.get("per_page", 50)),
            max_pages=int(opts.get("max_pages", 2)),
            source_tier=tier,
        )

    if source_type == "kev":
        return KevCollector(
            url=opts.get("url"),
            mirror_url=opts.get("mirror_url"),
            lookback_days=opts.get("lookback_days"),
        )

    if source_type in {"html", "html_advisories"}:
        url = opts.get("url")
        if not url:
            raise ValueError(f"html {name!r} requires url")
        return HtmlAdvisoriesCollector(
            source=name,
            url=url,
            source_tier=tier,
            default_products=opts.get("default_products"),
            include_keywords=opts.get("include_keywords"),
            max_items=int(opts.get("max_items", 80)),
            mode=str(opts.get("mode") or "cve_page"),
        )

    if source_type == "changelog":
        factory = _CHANGELOG_FACTORIES.get(opts.get("vendor") or name)
        if factory:
            return factory(name=name, source_tier=tier, **{
                k: v for k, v in opts.items() if k not in {"vendor", "source_tier", "tier", "name"}
            })
        url = opts.get("url")
        if not url:
            raise ValueError(f"changelog {name!r} requires url or known vendor")
        return ChangelogCollector(
            source=name,
            url=url,
            source_tier=tier,
            default_products=opts.get("default_products"),
            include_keywords=opts.get("include_keywords"),
            max_items=int(opts.get("max_items", 40)),
        )

    return None


def _default_tier(source_type: str) -> int:
    return {
        "kev": 1,
        "nvd": 1,
        "html": 1,
        "html_advisories": 1,
        "changelog": 1,
        "feed": 2,
        "github_advisories": 2,
        "wordfence": 3,
    }.get(source_type, 3)
