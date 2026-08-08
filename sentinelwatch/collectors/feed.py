"""Generic RSS/Atom collector — one instance per feed URL in config."""

from __future__ import annotations

import logging
from typing import Any

import feedparser

from sentinelwatch.collectors.base import (
    Collector,
    extract_cves,
    http_get,
    parse_date,
    stable_id,
)
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)


class FeedCollector(Collector):
    """
    Parametrized feed collector. Reused for vendor changelogs, distro errata,
    security blogs, and announcement lists that expose RSS/Atom.
    """

    def __init__(
        self,
        source: str,
        url: str,
        *,
        include_keywords: list[str] | None = None,
        exclude_keywords: list[str] | None = None,
        default_products: list[str] | None = None,
        max_entries: int = 100,
    ) -> None:
        self.name = source
        self.source = source
        self.url = url
        self.include_keywords = [k.lower() for k in (include_keywords or [])]
        self.exclude_keywords = [k.lower() for k in (exclude_keywords or [])]
        self.default_products = list(default_products or [])
        self.max_entries = max_entries

    def collect(self) -> list[Vulnerability]:
        resp = http_get(self.url)
        parsed = feedparser.parse(resp.text)
        if getattr(parsed, "bozo", False) and not parsed.entries:
            raise RuntimeError(
                f"Failed to parse feed {self.url}: {getattr(parsed, 'bozo_exception', '')}"
            )

        results: list[Vulnerability] = []
        for entry in parsed.entries[: self.max_entries]:
            vuln = self._entry_to_vuln(entry)
            if vuln is None:
                continue
            if not self._passes_filters(vuln):
                continue
            results.append(vuln)
        return results

    def _passes_filters(self, vuln: Vulnerability) -> bool:
        text = f"{vuln.title} {vuln.description}".lower()
        if self.exclude_keywords and any(k in text for k in self.exclude_keywords):
            return False
        if self.include_keywords:
            return any(k in text for k in self.include_keywords)
        return True

    def _entry_to_vuln(self, entry: Any) -> Vulnerability | None:
        title = (getattr(entry, "title", None) or "").strip()
        if not title:
            return None

        link = (getattr(entry, "link", None) or "").strip()
        summary = (
            getattr(entry, "summary", None)
            or getattr(entry, "description", None)
            or ""
        )
        if hasattr(summary, "strip"):
            summary = summary.strip()
        else:
            summary = str(summary)

        external = (
            getattr(entry, "id", None)
            or getattr(entry, "guid", None)
            or link
            or stable_id(self.source, title)
        )
        external_id = str(external).strip()

        published = parse_date(
            getattr(entry, "published", None)
            or getattr(entry, "updated", None)
            or getattr(entry, "created", None)
        )

        cves = extract_cves(f"{title} {summary}")
        products = list(self.default_products)
        for cve in cves:
            if cve not in products:
                products.append(cve)

        refs = [link] if link else []
        for cve in cves:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        return Vulnerability(
            external_id=external_id,
            source=self.source,
            title=title,
            description=summary,
            cvss_score=None,
            reported_severity=None,
            affected_products=products,
            published_date=published,
            url=link or self.url,
            references=refs,
        )
