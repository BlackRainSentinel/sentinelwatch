"""NVD API 2.0 — CPE-driven queries per taxonomy product (v3)."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability
from sentinelwatch.taxonomy import PRODUCTS, ProductSpec

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdCollector(Collector):
    name = "nvd"
    source_tier = 1
    schedule = "fast"

    def __init__(
        self,
        *,
        taxonomy: list[ProductSpec] | None = None,
        keywords: list[str] | None = None,
        lookback_days: int = 14,
        results_per_page: int = 50,
        api_key: str | None = None,
        sleep_seconds: float | None = None,
        source_tier: int = 1,
        use_cpe: bool = True,
    ) -> None:
        self.taxonomy = list(taxonomy) if taxonomy is not None else list(PRODUCTS)
        self.keywords = [k for k in (keywords or []) if k and k.strip()]
        self.lookback_days = lookback_days
        self.results_per_page = results_per_page
        self.api_key = (api_key or os.environ.get("NVD_API_KEY", "")).strip()
        self.source_tier = int(source_tier)
        self.use_cpe = use_cpe
        if sleep_seconds is not None:
            self.sleep_seconds = sleep_seconds
        else:
            self.sleep_seconds = 0.7 if self.api_key else 6.1

    def collect(self) -> list[Vulnerability]:
        seen: dict[str, Vulnerability] = {}
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.lookback_days)
        pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        queries: list[dict[str, Any]] = []
        if self.use_cpe:
            for spec in self.taxonomy:
                for vendor, product in spec.cpe_pairs:
                    cpe = f"cpe:2.3:a:{vendor}:{product}"
                    queries.append({"virtualMatchString": cpe, "label": spec.id})
        for kw in self.keywords:
            queries.append({"keywordSearch": kw, "label": f"kw:{kw}"})

        if not queries:
            raise RuntimeError("NVD collector has no CPE pairs or keywords configured")

        errors: list[str] = []
        for q in queries:
            label = q.get("label", "?")
            params = {k: v for k, v in q.items() if k != "label"}
            try:
                for vuln in self._query(pub_start, pub_end, **params):
                    seen[vuln.external_id] = vuln
            except Exception as exc:
                log.exception("NVD query failed for %s", label)
                errors.append(f"{label}: {exc}")
            time.sleep(self.sleep_seconds)

        if not seen and errors:
            raise RuntimeError(
                "NVD produced no results; failures: " + "; ".join(errors[:8])
            )
        return list(seen.values())

    def _query(
        self, pub_start: str, pub_end: str, **extra: Any
    ) -> list[Vulnerability]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params: dict[str, Any] = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": self.results_per_page,
            "startIndex": 0,
            **extra,
        }
        resp = http_get(NVD_URL, headers=headers, params=params, timeout=90.0)
        data = resp.json()
        vulns: list[Vulnerability] = []
        for item in data.get("vulnerabilities") or []:
            parsed = self._parse_cve(item.get("cve") or {})
            if parsed:
                vulns.append(parsed)
        return vulns

    def _parse_cve(self, cve: dict[str, Any]) -> Optional[Vulnerability]:
        cve_id = (cve.get("id") or "").strip().upper()
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
        products, versions = self._products_and_versions(cve)
        refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]

        return Vulnerability(
            external_id=cve_id,
            source=self.name,
            title=cve_id if not description else f"{cve_id}: {description[:120]}",
            description=description,
            cvss_score=score,
            reported_severity=severity,
            affected_products=products,
            affected_versions=versions,
            cve_ids=[cve_id],
            published_date=parse_date(cve.get("published")),
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            references=refs,
            source_tier=self.source_tier,
        )

    @staticmethod
    def _cvss(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
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
    def _products_and_versions(cve: dict[str, Any]) -> tuple[list[str], list[str]]:
        products: list[str] = []
        versions: list[str] = []
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria") or ""
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        label = f"{parts[3]}:{parts[4]}"
                        if label not in products:
                            products.append(label)
                        if len(parts) >= 6 and parts[5] not in {"*", "-"}:
                            versions.append(parts[5])
                    if match.get("versionStartIncluding"):
                        versions.append(f">={match['versionStartIncluding']}")
                    if match.get("versionEndExcluding"):
                        versions.append(f"<{match['versionEndExcluding']}")
                    if match.get("versionEndIncluding"):
                        versions.append(f"<={match['versionEndIncluding']}")
        # dedupe versions preserving order
        seen_v: set[str] = set()
        uniq_v = []
        for v in versions:
            if v not in seen_v:
                seen_v.add(v)
                uniq_v.append(v)
        return products[:40], uniq_v[:20]
