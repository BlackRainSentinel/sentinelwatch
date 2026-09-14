"""Normalized vulnerability schema (v3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


SEVERITY_TIERS = ("critical", "high", "medium", "low", "unknown")
SOURCE_TIERS = (1, 2, 3)
CHANNELS = ("critical", "digest", "wordpress")
CATEGORIES = (
    "panel",
    "webserver",
    "mail",
    "database",
    "dns",
    "ftp",
    "security",
    "backup",
    "php",
    "wordpress",
    "os",
    "other",
)


@dataclass
class Vulnerability:
    """Collector output. Classification / scoring fields filled post-dedup."""

    external_id: str
    source: str
    title: str
    description: str
    cvss_score: Optional[float]
    reported_severity: Optional[str]
    affected_products: list[str]
    published_date: Optional[datetime]
    url: str
    references: list[str] = field(default_factory=list)

    cve_ids: list[str] = field(default_factory=list)
    # Free-text / CPE version hints when collectors can extract them
    affected_versions: list[str] = field(default_factory=list)

    source_tier: int = 3
    category: str = "other"
    severity_tier: str = "unknown"
    product_match: bool = False
    matched_products: list[str] = field(default_factory=list)
    in_kev: bool = False
    in_hosting_kev: bool = False
    always_alert: bool = False

    # v3 applicability + ranking
    version_applicable: bool = True  # True when unknown or overlaps fleet
    version_unknown: bool = True
    alert_score: float = 0.0
    blast_radius: str = "normal"  # normal | elevated | critical
    impact_note: str = ""
    channel: str = "digest"  # critical | digest | wordpress
    thread_key: str = ""  # links pre-CVE → CVE family

    @property
    def dedup_key(self) -> str:
        return f"{self.source}:{self.external_id}"

    @property
    def fleet_match(self) -> bool:
        return self.product_match

    @fleet_match.setter
    def fleet_match(self, value: bool) -> None:
        self.product_match = bool(value)
