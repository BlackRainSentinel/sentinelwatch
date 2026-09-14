"""
HTML / plaintext advisory list collector.

Used for Tier-1 vendor pages that publish security notices as HTML (or the
Debian DSA plaintext list) rather than RSS. Extracts CVE IDs + surrounding
context; does not attempt full HTML DOM scraping frameworks.
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
)
from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# Debian DSA list lines: [DD MMM YYYY] DSA-XXXX-Y pkg - description
_DSA_LINE_RE = re.compile(
    r"^\[([^\]]+)\]\s+(DSA-\d+(?:-\d+)?)\s+(.+)$",
    re.MULTILINE,
)


def _strip_html(text: str) -> str:
    text = _TAG_RE.sub(" ", text)
    text = unescape(text)
    return _WS_RE.sub(" ", text).strip()


class HtmlAdvisoriesCollector(Collector):
    """
    Fetch a URL and emit one Vulnerability per distinct CVE found on the page,
    optionally filtered by include_keywords. default_products seed taxonomy match.
    """

    def __init__(
        self,
        source: str,
        url: str,
        *,
        source_tier: int = 1,
        default_products: list[str] | None = None,
        include_keywords: list[str] | None = None,
        max_items: int = 80,
        mode: str = "cve_page",  # cve_page | debian_dsa
    ) -> None:
        self.name = source
        self.source = source
        self.url = url
        self.source_tier = int(source_tier)
        self.default_products = list(default_products or [])
        self.include_keywords = [k.lower() for k in (include_keywords or [])]
        self.max_items = max_items
        self.mode = mode

    def collect(self) -> list[Vulnerability]:
        resp = http_get(self.url, timeout=90.0)
        text = resp.text
        if self.mode == "debian_dsa":
            return self._parse_debian_dsa(text)
        return self._parse_cve_page(text)

    def _passes(self, blob: str) -> bool:
        if not self.include_keywords:
            return True
        low = blob.lower()
        return any(k in low for k in self.include_keywords)

    def _parse_cve_page(self, raw: str) -> list[Vulnerability]:
        plain = _strip_html(raw)
        # Split into rough chunks around CVE mentions for title/context
        cves = extract_cves(plain)
        results: list[Vulnerability] = []
        seen: set[str] = set()

        for cve in cves:
            if cve in seen:
                continue
            seen.add(cve)
            # Grab ~200 chars of context around first mention
            m = re.search(re.escape(cve), plain, flags=re.I)
            if not m:
                continue
            start = max(0, m.start() - 80)
            end = min(len(plain), m.end() + 160)
            ctx = plain[start:end].strip()
            if not self._passes(ctx):
                continue
            results.append(
                Vulnerability(
                    external_id=cve,
                    source=self.source,
                    title=f"{cve} ({self.source})",
                    description=ctx,
                    cvss_score=None,
                    reported_severity=None,
                    affected_products=list(self.default_products),
                    cve_ids=[cve],
                    published_date=None,
                    url=self.url,
                    references=[self.url, f"https://nvd.nist.gov/vuln/detail/{cve}"],
                    source_tier=self.source_tier,
                )
            )
            if len(results) >= self.max_items:
                break
        return results

    def _parse_debian_dsa(self, raw: str) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        for m in _DSA_LINE_RE.finditer(raw):
            date_s, dsa_id, rest = m.group(1), m.group(2), m.group(3).strip()
            blob = f"{dsa_id} {rest}"
            if not self._passes(blob):
                continue
            cves = extract_cves(rest)
            products = list(self.default_products)
            # First token before " - " is often the package name
            pkg = rest.split(" - ", 1)[0].strip()
            if pkg:
                products.append(pkg)
            results.append(
                Vulnerability(
                    external_id=dsa_id,
                    source=self.source,
                    title=f"{dsa_id}: {rest[:140]}",
                    description=rest,
                    cvss_score=None,
                    reported_severity=None,
                    affected_products=products,
                    cve_ids=cves,
                    published_date=parse_date(date_s),
                    url=f"https://www.debian.org/security/{dsa_id}",
                    references=[self.url],
                    source_tier=self.source_tier,
                )
            )
            if len(results) >= self.max_items:
                break
        return results
