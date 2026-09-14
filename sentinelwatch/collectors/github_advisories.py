"""GitHub Security Advisories — scoped to hosting-relevant packages."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

GHSA_URL = "https://api.github.com/advisories"

# Default relevance filter — package name / summary must hit one of these.
DEFAULT_INCLUDE = [
    "wordpress",
    "woocommerce",
    "php",
    "apache",
    "httpd",
    "nginx",
    "exim",
    "dovecot",
    "mariadb",
    "mysql",
    "openssl",
    "cpanel",
    "litespeed",
    "clamav",
    "bind",
    "powerdns",
    "spamassassin",
    "pure-ftpd",
    "mongodb",
]


class GithubAdvisoriesCollector(Collector):
    name = "github_advisories"
    source_tier = 2

    def __init__(
        self,
        ecosystems: list[str] | None = None,
        *,
        include_keywords: list[str] | None = None,
        per_page: int = 50,
        max_pages: int = 2,
        token: str | None = None,
        source_tier: int = 2,
    ) -> None:
        self.ecosystems = ecosystems or ["composer"]
        self.include_keywords = [
            k.lower() for k in (include_keywords or DEFAULT_INCLUDE)
        ]
        self.per_page = per_page
        self.max_pages = max_pages
        self.token = (
            token
            or os.environ.get("GITHUB_TOKEN", "")
            or os.environ.get("GH_TOKEN", "")
        ).strip()
        self.source_tier = int(source_tier)

    def collect(self) -> list[Vulnerability]:
        seen: dict[str, Vulnerability] = {}
        for eco in self.ecosystems:
            try:
                for vuln in self._fetch_ecosystem(eco):
                    if self._relevant(vuln):
                        seen[vuln.external_id] = vuln
            except Exception:
                log.exception("GitHub advisories failed for ecosystem=%r", eco)
                raise
        return list(seen.values())

    def _relevant(self, vuln: Vulnerability) -> bool:
        text = f"{vuln.title} {vuln.description} {' '.join(vuln.affected_products)}".lower()
        return any(k in text for k in self.include_keywords)

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

        cve_ids: list[str] = []
        cve_id = item.get("cve_id")
        if cve_id:
            cve_ids.append(str(cve_id).upper())
        # Also pull CVEs mentioned in text
        for m in re.finditer(r"CVE-\d{4}-\d{4,}", f"{summary} {description}", re.I):
            cve_ids.append(m.group(0).upper())
        cve_ids = sorted(set(cve_ids))

        refs: list[str] = []
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
            cve_ids=cve_ids,
            published_date=parse_date(
                item.get("published_at") or item.get("updated_at")
            ),
            url=html_url,
            references=refs,
            source_tier=self.source_tier,
        )
