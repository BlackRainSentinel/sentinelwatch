"""GitHub Security Advisories via the public REST API (ecosystem filtered)."""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

GHSA_URL = "https://api.github.com/advisories"


class GithubAdvisoriesCollector(Collector):
    name = "github_advisories"

    def __init__(
        self,
        ecosystems: list[str] | None = None,
        *,
        per_page: int = 50,
        max_pages: int = 2,
        token: str | None = None,
    ) -> None:
        # Shared hosting focus: php packs + npm themes/plugins adjacent
        self.ecosystems = ecosystems or ["composer", "npm", "pip"]
        self.per_page = per_page
        self.max_pages = max_pages
        self.token = (
            token
            or os.environ.get("GITHUB_TOKEN", "")
            or os.environ.get("GH_TOKEN", "")
        ).strip()

    def collect(self) -> list[Vulnerability]:
        seen: dict[str, Vulnerability] = {}
        for eco in self.ecosystems:
            try:
                for vuln in self._fetch_ecosystem(eco):
                    seen[vuln.external_id] = vuln
            except Exception:
                log.exception("GitHub advisories failed for ecosystem=%r", eco)
        return list(seen.values())

    def _fetch_ecosystem(self, ecosystem: str) -> list[Vulnerability]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        results: list[Vulnerability] = []
        for page in range(1, self.max_pages + 1):
            params = {
                "ecosystem": ecosystem,
                "per_page": self.per_page,
                "page": page,
            }
            resp = http_get(GHSA_URL, headers=headers, params=params, timeout=60.0)
            data = resp.json()
            if not isinstance(data, list) or not data:
                break
            for item in data:
                vuln = self._parse(item, ecosystem)
                if vuln:
                    results.append(vuln)
        return results

    def _parse(
        self, item: dict[str, Any], ecosystem: str
    ) -> Optional[Vulnerability]:
        ghsa = (item.get("ghsa_id") or item.get("id") or "").strip()
        summary = (item.get("summary") or "").strip()
        if not ghsa or not summary:
            return None

        description = (item.get("description") or summary).strip()
        score = None
        severity = item.get("severity")
        cvss = item.get("cvss") or {}
        if isinstance(cvss, dict) and cvss.get("score") is not None:
            try:
                score = float(cvss["score"])
            except (TypeError, ValueError):
                score = None

        products = [ecosystem]
        for v in item.get("vulnerabilities") or []:
            pkg = (v.get("package") or {}).get("name")
            if pkg:
                products.append(f"{ecosystem}:{pkg}")

        cve_id = item.get("cve_id")
        if cve_id:
            products.append(str(cve_id).upper())

        refs = []
        html_url = item.get("html_url") or f"https://github.com/advisories/{ghsa}"
        refs.append(html_url)
        for r in item.get("references") or []:
            if isinstance(r, str):
                refs.append(r)
            elif isinstance(r, dict) and r.get("url"):
                refs.append(r["url"])

        return Vulnerability(
            external_id=ghsa,
            source=self.name,
            title=f"{ghsa}: {summary}",
            description=description,
            cvss_score=score,
            reported_severity=severity if isinstance(severity, str) else None,
            affected_products=products,
            published_date=parse_date(
                item.get("published_at") or item.get("updated_at")
            ),
            url=html_url,
            references=refs,
        )
