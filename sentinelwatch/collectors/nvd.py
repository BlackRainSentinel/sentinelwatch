"""NVD API 2.0 collector — keyword-filtered queries against hosting stack terms."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdCollector(Collector):
    name = "nvd"

    def __init__(
        self,
        keywords: list[str],
        *,
        lookback_days: int = 14,
        results_per_page: int = 50,
        api_key: str | None = None,
        sleep_seconds: float | None = None,
    ) -> None:
        self.keywords = [k for k in keywords if k and k.strip()]
        self.lookback_days = lookback_days
        self.results_per_page = results_per_page
        self.api_key = (api_key or os.environ.get("NVD_API_KEY", "")).strip()
        # Without a key NVD asks for ~6s between requests; with key ~0.6s.
        if sleep_seconds is not None:
            self.sleep_seconds = sleep_seconds
        else:
            self.sleep_seconds = 0.7 if self.api_key else 6.1

    def collect(self) -> list[Vulnerability]:
        seen: dict[str, Vulnerability] = {}
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.lookback_days)
        # NVD expects ISO-8601 with milliseconds
        pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        for kw in self.keywords:
            try:
                for vuln in self._query_keyword(kw, pub_start, pub_end):
                    seen[vuln.external_id] = vuln
            except Exception:
                log.exception("NVD query failed for keyword=%r", kw)
            time.sleep(self.sleep_seconds)

        return list(seen.values())

    def _query_keyword(
        self, keyword: str, pub_start: str, pub_end: str
    ) -> list[Vulnerability]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": self.results_per_page,
            "startIndex": 0,
        }
        resp = http_get(NVD_URL, headers=headers, params=params, timeout=90.0)
        data = resp.json()
        vulns: list[Vulnerability] = []
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            parsed = self._parse_cve(cve)
            if parsed:
                vulns.append(parsed)
        return vulns

    def _parse_cve(self, cve: dict[str, Any]) -> Optional[Vulnerability]:
        cve_id = (cve.get("id") or "").strip()
        if not cve_id:
            return None

        description = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                description = (d.get("value") or "").strip()
                break
        if not description and cve.get("descriptions"):
            description = (cve["descriptions"][0].get("value") or "").strip()

        score, severity = self._cvss(cve)
        products = self._products(cve)
        published = parse_date(cve.get("published"))
        refs = []
        for r in cve.get("references") or []:
            url = r.get("url")
            if url:
                refs.append(url)

        return Vulnerability(
            external_id=cve_id,
            source=self.name,
            title=cve_id if not description else f"{cve_id}: {description[:120]}",
            description=description,
            cvss_score=score,
            reported_severity=severity,
            affected_products=products,
            published_date=published,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            references=refs,
        )

    @staticmethod
    def _cvss(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            # Prefer Primary
            primary = next(
                (e for e in entries if e.get("type") == "Primary"), entries[0]
            )
            data = primary.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or primary.get("baseSeverity")
            try:
                return (float(score) if score is not None else None, sev)
            except (TypeError, ValueError):
                return None, sev
        return None, None

    @staticmethod
    def _products(cve: dict[str, Any]) -> list[str]:
        products: list[str] = []
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria") or ""
                    # cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor, product = parts[3], parts[4]
                        label = f"{vendor}:{product}"
                        if label not in products:
                            products.append(label)
        return products[:40]
