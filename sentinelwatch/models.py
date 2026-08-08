"""Normalized vulnerability schema shared by all collectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


SEVERITY_TIERS = ("critical", "high", "medium", "low", "unknown")
CATEGORIES = (
    "panel",
    "webserver",
    "mail",
    "database",
    "php",
    "os",
    "wordpress",
    "other",
)


@dataclass
class Vulnerability:
    """Collector output. Classification fields are filled after dedup."""

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

    category: str = "other"
    severity_tier: str = "unknown"
    fleet_match: bool = False

    @property
    def dedup_key(self) -> str:
        return f"{self.source}:{self.external_id}"
