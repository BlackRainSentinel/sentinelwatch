"""Wordfence Threat Intel production JSON feed (no token required)."""

from __future__ import annotations

import logging
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

DEFAULT_URL = (
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
)

# Re-export alias used by the registry
__all__ = ["DEFAULT_URL", "WordfenceCollector"]


class WordfenceCollector(Collector):
    name = "wordfence"

    def __init__(
        self,
        url: str = DEFAULT_URL,
        *,
        max_items: int = 200,
    ) -> None:
        self.url = url
        self.max_items = max_items

    def collect(self) -> list[Vulnerability]:
        resp = http_get(self.url, timeout=120.0)
        data = resp.json()
        # API returns a dict keyed by vulnerability id, or occasionally a list
        if isinstance(data, dict):
            items = list(data.values())
        elif isinstance(data, list):
            items = data
        else:
            raise RuntimeError(f"Unexpected Wordfence payload type: {type(data)}")

        # Prefer newest — sort by published if present
        def sort_key(item: dict[str, Any]) -> str:
            return str(item.get("published") or item.get("updated") or "")

        items = sorted(items, key=sort_key, reverse=True)[: self.max_items]

        results: list[Vulnerability] = []
        for item in items:
            vuln = self._parse(item)
            if vuln:
                results.append(vuln)
        return results

    def _parse(self, item: dict[str, Any]) -> Optional[Vulnerability]:
        ext_id = str(
            item.get("id")
            or item.get("uuid")
            or item.get("cve")
            or ""
        ).strip()
        title = (item.get("title") or "").strip()
        if not ext_id or not title:
            return None

        description = (item.get("description") or "").strip()
        score = self._score(item)
        severity = item.get("severity") or item.get("cvss_rating")
        if isinstance(severity, str):
            severity = severity.lower()

        products: list[str] = ["wordpress"]
        software = item.get("software") or []
        if isinstance(software, list):
            for s in software:
                if isinstance(s, dict):
                    name = s.get("name") or s.get("slug")
                    stype = s.get("type")
                    if name:
                        label = f"{stype}:{name}" if stype else str(name)
                        products.append(label)
                elif isinstance(s, str):
                    products.append(s)

        cve = item.get("cve")
        if cve:
            products.append(str(cve).upper())

        refs: list[str] = []
        url = (item.get("url") or item.get("references") or "")
        if isinstance(url, list):
            refs.extend(str(u) for u in url if u)
            url = refs[0] if refs else ""
        elif isinstance(url, str) and url:
            refs.append(url)
        else:
            url = ""
            for key in ("references", "reference"):
                val = item.get(key)
                if isinstance(val, list):
                    refs.extend(str(u) for u in val if u)
                elif isinstance(val, str) and val:
                    refs.append(val)
            if refs and not url:
                url = refs[0]

        published = parse_date(item.get("published") or item.get("updated"))

        return Vulnerability(
            external_id=ext_id,
            source=self.name,
            title=title,
            description=description,
            cvss_score=score,
            reported_severity=severity if isinstance(severity, str) else None,
            affected_products=products,
            published_date=published,
            url=url or f"https://www.wordfence.com/threat-intel/vulnerabilities/",
            references=refs,
        )

    @staticmethod
    def _score(item: dict[str, Any]) -> Optional[float]:
        for key in ("cvss_score", "cvss", "score"):
            raw = item.get(key)
            if raw is None:
                continue
            if isinstance(raw, dict):
                raw = raw.get("score") or raw.get("baseScore")
            try:
                return float(raw)
            except (TypeError, ValueError):
                continue
        return None
