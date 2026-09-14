"""
Gap-fill Tier-1 collectors for vendors without stable RSS.

Each targets a verified URL; failures are isolated by the pipeline.
Fixtures under tests/fixtures/ can lock HTML shape in CI.
"""

from __future__ import annotations

import logging
import re
from html import unescape

from sentinelwatch.collectors.base import (
    Collector,
    extract_cves,
    http_get,
    parse_date,
    stable_id,
)
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_LINK_RE = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.I | re.S,
)


def _plain(html: str) -> str:
    return _WS_RE.sub(" ", unescape(_TAG_RE.sub(" ", html))).strip()


class ChangelogCollector(Collector):
    """
    Generic changelog / forum / docs page scraper.
    Emits entries from links or CVE mentions with default_products seeded.
    """

    schedule = "fast"

    def __init__(
        self,
        source: str,
        url: str,
        *,
        source_tier: int = 1,
        default_products: list[str] | None = None,
        include_keywords: list[str] | None = None,
        max_items: int = 40,
    ) -> None:
        self.name = source
        self.source = source
        self.url = url
        self.source_tier = int(source_tier)
        self.default_products = list(default_products or [])
        self.include_keywords = [k.lower() for k in (include_keywords or [])]
        self.max_items = max_items

    def collect(self) -> list[Vulnerability]:
        resp = http_get(self.url, timeout=90.0)
        html = resp.text
        # Plaintext changelogs (CSF etc.)
        if "text/plain" in (resp.headers.get("content-type") or "") or self.url.endswith(
            ".txt"
        ):
            return self._parse_plaintext(html)
        plain = _plain(html)
        results: list[Vulnerability] = []
        seen: set[str] = set()

        # Prefer security-ish links
        for href, label_html in _LINK_RE.findall(html):
            label = _plain(label_html)
            blob = f"{label} {href}".lower()
            if self.include_keywords and not any(k in blob for k in self.include_keywords):
                if not extract_cves(label):
                    continue
            if href.startswith("/"):
                from urllib.parse import urljoin

                href = urljoin(self.url, href)
            if not href.startswith("http"):
                continue
            ext = stable_id(self.source, href, label)
            if ext in seen:
                continue
            seen.add(ext)
            cves = extract_cves(f"{label} {href}")
            results.append(
                Vulnerability(
                    external_id=ext,
                    source=self.source,
                    title=label[:200] or f"{self.source} advisory",
                    description=label,
                    cvss_score=None,
                    reported_severity=None,
                    affected_products=list(self.default_products),
                    cve_ids=cves,
                    published_date=None,
                    url=href,
                    references=[href, self.url],
                    source_tier=self.source_tier,
                )
            )
            if len(results) >= self.max_items:
                return results

        if not results:
            for cve in extract_cves(plain)[: self.max_items]:
                results.append(
                    Vulnerability(
                        external_id=cve,
                        source=self.source,
                        title=f"{cve} ({self.source})",
                        description=plain[:500],
                        cvss_score=None,
                        reported_severity=None,
                        affected_products=list(self.default_products),
                        cve_ids=[cve],
                        published_date=None,
                        url=self.url,
                        references=[self.url],
                        source_tier=self.source_tier,
                    )
                )
        return results

    def _parse_plaintext(self, text: str) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        # Split on blank lines / version headers
        chunks = re.split(r"\n(?=\d+\.\d+|v\d+|\[)", text)
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            low = chunk.lower()
            if self.include_keywords and not any(k in low for k in self.include_keywords):
                if not extract_cves(chunk):
                    continue
            title = chunk.split("\n", 1)[0][:200]
            ext = stable_id(self.source, title)
            results.append(
                Vulnerability(
                    external_id=ext,
                    source=self.source,
                    title=title or f"{self.source} changelog",
                    description=chunk[:1000],
                    cvss_score=None,
                    reported_severity=None,
                    affected_products=list(self.default_products),
                    cve_ids=extract_cves(chunk),
                    published_date=parse_date(None),
                    url=self.url,
                    references=[self.url],
                    source_tier=self.source_tier,
                )
            )
            if len(results) >= self.max_items:
                break
        return results

# Convenience constructors used by registry defaults
def directadmin_collector(**opts) -> ChangelogCollector:
    return ChangelogCollector(
        source=opts.get("name") or "directadmin",
        url=opts.get("url")
        or "https://www.directadmin.com/changelog.php",
        source_tier=int(opts.get("source_tier", 1)),
        default_products=opts.get("default_products") or ["directadmin:directadmin"],
        include_keywords=opts.get("include_keywords")
        or ["security", "cve", "fix", "vulnerab", "exploit"],
        max_items=int(opts.get("max_items", 40)),
    )


def csf_collector(**opts) -> ChangelogCollector:
    return ChangelogCollector(
        source=opts.get("name") or "csf",
        url=opts.get("url")
        or "https://download.configserver.com/csf/changelog.txt",
        source_tier=int(opts.get("source_tier", 1)),
        default_products=opts.get("default_products") or ["configserver:csf"],
        include_keywords=opts.get("include_keywords")
        or ["security", "cve", "fix", "vulnerab", "exploit", "lfd"],
        max_items=int(opts.get("max_items", 40)),
    )


def pureftpd_collector(**opts) -> ChangelogCollector:
    return ChangelogCollector(
        source=opts.get("name") or "pureftpd",
        url=opts.get("url") or "https://www.pureftpd.org/project/pure-ftpd/",
        source_tier=int(opts.get("source_tier", 1)),
        default_products=opts.get("default_products") or ["pureftpd:pure-ftpd"],
        include_keywords=opts.get("include_keywords")
        or ["security", "cve", "vulnerab", "advisory"],
        max_items=int(opts.get("max_items", 40)),
    )


def jetbackup_collector(**opts) -> ChangelogCollector:
    return ChangelogCollector(
        source=opts.get("name") or "jetbackup",
        url=opts.get("url") or "https://www.jetbackup.com/changelog/",
        source_tier=int(opts.get("source_tier", 1)),
        default_products=opts.get("default_products") or ["jetbackup:jetbackup"],
        include_keywords=opts.get("include_keywords")
        or ["security", "cve", "vulnerab", "fix", "advisory"],
        max_items=int(opts.get("max_items", 40)),
    )


def bind_collector(**opts) -> ChangelogCollector:
    return ChangelogCollector(
        source=opts.get("name") or "isc_bind",
        url=opts.get("url") or "https://kb.isc.org/docs",
        source_tier=int(opts.get("source_tier", 1)),
        default_products=opts.get("default_products") or ["isc:bind"],
        include_keywords=opts.get("include_keywords")
        or ["bind", "security", "cve", "advisory", "vulnerab"],
        max_items=int(opts.get("max_items", 40)),
    )
