"""CISA Known Exploited Vulnerabilities (KEV) catalog collector."""

from __future__ import annotations

import logging
from typing import Any

from sentinelwatch.collectors.base import Collector, http_get, parse_date
from sentinelwatch.models import Vulnerability
from sentinelwatch.taxonomy import PRODUCTS, ProductSpec

log = logging.getLogger(__name__)

# cisa.gov intermittently blocks datacenter UAs (403); GitHub mirror is authoritative sync.
PRIMARY_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)


class KevCollector(Collector):
    """
    Pulls the KEV catalog. Emits hosting-taxonomy-relevant entries as findings.
    Also exposes the raw catalog via last_catalog for DB enrichment of all CVEs.
    """

    name = "cisa_kev"
    source_tier = 1

    def __init__(
        self,
        url: str | None = None,
        mirror_url: str | None = None,
        taxonomy: list[ProductSpec] | None = None,
        lookback_days: int | None = None,
    ) -> None:
        self.url = url or PRIMARY_URL
        self.mirror_url = mirror_url or MIRROR_URL
        self.taxonomy = list(taxonomy) if taxonomy is not None else list(PRODUCTS)
        self.lookback_days = lookback_days
        self.last_catalog: list[dict[str, str]] = []

    def collect(self) -> list[Vulnerability]:
        data = self._fetch_json()
        vulns_raw = data.get("vulnerabilities") or []
        if not isinstance(vulns_raw, list):
            raise RuntimeError("KEV feed missing vulnerabilities array")

        catalog: list[dict[str, str]] = []
        results: list[Vulnerability] = []

        for item in vulns_raw:
            if not isinstance(item, dict):
                continue
            cve = (item.get("cveID") or "").upper().strip()
            if not cve:
                continue
            vendor = (item.get("vendorProject") or "").strip()
            product = (item.get("product") or "").strip()
            catalog.append(
                {
                    "cve_id": cve,
                    "vendor": vendor,
                    "product": product,
                    "date_added": str(item.get("dateAdded") or ""),
                }
            )

            if not self._relevant(vendor, product, item):
                continue

            name = (item.get("vulnerabilityName") or cve).strip()
            desc = (item.get("shortDescription") or "").strip()
            notes = (item.get("notes") or "").strip()
            url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            refs = [url]
            if notes:
                for part in notes.split(";"):
                    part = part.strip()
                    if part.startswith("http"):
                        refs.append(part)

            results.append(
                Vulnerability(
                    external_id=cve,
                    source=self.name,
                    title=f"[KEV] {name}",
                    description=desc or name,
                    cvss_score=None,
                    reported_severity="KEV",
                    affected_products=self._product_tokens(vendor, product),
                    cve_ids=[cve],
                    published_date=parse_date(item.get("dateAdded")),
                    url=refs[1] if len(refs) > 1 else url,
                    references=refs,
                    source_tier=1,
                    in_kev=True,
                    always_alert=True,
                )
            )

        self.last_catalog = catalog
        log.info("KEV catalog: %d total, %d taxonomy-relevant", len(catalog), len(results))
        return results

    def _fetch_json(self) -> dict[str, Any]:
        errors: list[str] = []
        for url in (self.url, self.mirror_url):
            try:
                resp = http_get(url, timeout=90.0)
                data = resp.json()
                if isinstance(data, dict) and data.get("vulnerabilities") is not None:
                    return data
                errors.append(f"{url}: unexpected payload")
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                log.warning("KEV fetch failed for %s: %s", url, exc)
        raise RuntimeError("KEV fetch failed for all URLs: " + " | ".join(errors))

    def _relevant(self, vendor: str, product: str, item: dict[str, Any]) -> bool:
        blob = f"{vendor} {product} {item.get('vulnerabilityName', '')}".lower()
        for spec in self.taxonomy:
            for alias in spec.aliases:
                if alias.lower() in blob:
                    return True
            if spec.vendor.lower() in blob or spec.product.lower().replace("_", " ") in blob:
                return True
            for cv, cp in spec.cpe_pairs:
                if cv.lower() in blob and cp.lower().replace("_", " ") in blob:
                    return True
        return False

    @staticmethod
    def _product_tokens(vendor: str, product: str) -> list[str]:
        tokens: list[str] = []
        if vendor and product:
            tokens.append(f"{vendor.lower().replace(' ', '_')}:{product.lower().replace(' ', '_')}")
        if product:
            tokens.append(product)
        if vendor:
            tokens.append(vendor)
        return tokens
