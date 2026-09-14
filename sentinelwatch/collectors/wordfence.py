"""Wordfence Threat Intel production feed — v3 API (Bearer key required)."""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

DEFAULT_URL = (
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
)


class WordfenceCollector(Collector):
    """
    Wordfence Intelligence v3. Requires WORDFENCE_API_KEY (free account key).
    Auth: Authorization: Bearer <key>
    """

    name = "wordfence"
    source_tier = 3

    def __init__(
        self,
        url: str = DEFAULT_URL,
        *,
        api_key: str | None = None,
        max_items: int = 200,
        source_tier: int = 3,
    ) -> None:
        self.url = url or DEFAULT_URL
        self.api_key = (api_key or os.environ.get("WORDFENCE_API_KEY", "")).strip()
        self.max_items = max_items
        self.source_tier = int(source_tier)

    def collect(self) -> list[Vulnerability]:
        if not self.api_key:
            raise RuntimeError(
                "Wordfence v3 requires WORDFENCE_API_KEY "
                "(free key from wordfence.com account → Integrations). "
                "v2 endpoint is dead since 2026-03-09."
            )

        resp = http_get(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=120.0,
        )
        data = resp.json()
        if isinstance(data, dict):
            items = list(data.values())
        elif isinstance(data, list):
            items = data
        else:
            raise RuntimeError(f"Unexpected Wordfence payload type: {type(data)}")

        def sort_key(item: dict[str, Any]) -> str:
            return str(item.get("published") or item.get("updated") or "")

        items = sorted(
            (i for i in items if isinstance(i, dict)),
            key=sort_key,
            reverse=True,
        )[: self.max_items]

        results: list[Vulnerability] = []
        for item in items:
            vuln = self._parse(item)
            if vuln:
                results.append(vuln)
        return results

    def _parse(self, item: dict[str, Any]) -> Optional[Vulnerability]:
        ext_id = str(item.get("id") or item.get("uuid") or "").strip()
        title = (item.get("title") or "").strip()
        if not ext_id or not title:
            return None

        description = (item.get("description") or "").strip()
        score = self._score(item)
        severity = item.get("severity")
        if isinstance(item.get("cvss"), dict):
            severity = severity or item["cvss"].get("rating")
        if isinstance(severity, str):
            severity = severity.lower()

        products: list[str] = ["wordpress:wordpress"]
        software = item.get("software") or []
        if isinstance(software, list):
            for s in software:
                if not isinstance(s, dict):
                    continue
                name = s.get("name") or s.get("slug")
                stype = s.get("type")
                slug = s.get("slug")
                if slug:
                    products.append(f"wordpress:{stype or 'software'}:{slug}")
                elif name:
                    products.append(str(name))

        cve_ids: list[str] = []
        cve = item.get("cve")
        if cve:
            cve_ids.append(str(cve).upper())

        refs: list[str] = []
        for key in ("references", "reference"):
            val = item.get(key)
            if isinstance(val, list):
                refs.extend(str(u) for u in val if u)
            elif isinstance(val, str) and val:
                refs.append(val)
        cve_link = item.get("cve_link")
        if cve_link:
            refs.append(str(cve_link))

        url = refs[0] if refs else "https://www.wordfence.com/threat-intel/vulnerabilities/"

        return Vulnerability(
            external_id=ext_id,
            source=self.name,
            title=title,
            description=description,
            cvss_score=score,
            reported_severity=severity if isinstance(severity, str) else None,
            affected_products=products,
            cve_ids=cve_ids,
            published_date=parse_date(item.get("published") or item.get("updated")),
            url=url,
            references=refs,
            source_tier=self.source_tier,
        )

    @staticmethod
    def _score(item: dict[str, Any]) -> Optional[float]:
        cvss = item.get("cvss")
        if isinstance(cvss, dict) and cvss.get("score") is not None:
            try:
                return float(cvss["score"])
            except (TypeError, ValueError):
                pass
        for key in ("cvss_score", "score"):
            raw = item.get(key)
            if raw is None:
                continue
            try:
                return float(raw)
            except (TypeError, ValueError):
                continue
        return None
