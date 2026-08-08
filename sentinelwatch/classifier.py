"""Classify new findings: category, severity_tier, fleet_match."""

from __future__ import annotations

from typing import Iterable

from sentinelwatch.models import Vulnerability


# Keyword buckets for category — first match wins, ordered by specificity.
CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (
        "panel",
        (
            "cpanel",
            "whm",
            "directadmin",
            "direct admin",
            "plesk",
        ),
    ),
    (
        "webserver",
        (
            "litespeed",
            "openlitespeed",
            "apache",
            "httpd",
            "nginx",
        ),
    ),
    (
        "mail",
        (
            "exim",
            "dovecot",
            "postfix",
            "mailman",
        ),
    ),
    (
        "database",
        (
            "mariadb",
            "mysql",
            "postgresql",
            "postgres",
        ),
    ),
    (
        "php",
        (
            "php",
            "php-fpm",
            "opcache",
        ),
    ),
    (
        "wordpress",
        (
            "wordpress",
            "wp-cli",
            "woocommerce",
            "wordfence",
            "wp plugin",
            "wp theme",
        ),
    ),
    (
        "os",
        (
            "almalinux",
            "cloudlinux",
            "ubuntu",
            "centos",
            "rhel",
            "debian",
            "kernel",
            "openssl",
            "glibc",
        ),
    ),
]


def severity_tier(cvss: float | None) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _haystack(vuln: Vulnerability) -> str:
    parts = [
        vuln.title or "",
        vuln.description or "",
        " ".join(vuln.affected_products or []),
    ]
    return " ".join(parts).lower()


def classify_category(vuln: Vulnerability) -> str:
    text = _haystack(vuln)
    for category, keywords in CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in text:
                return category
    return "other"


def fleet_match(vuln: Vulnerability, fleet_software: Iterable[str]) -> bool:
    """True when title/description/products overlap the operator fleet list."""
    text = _haystack(vuln)
    products_lower = [p.lower() for p in (vuln.affected_products or [])]
    for item in fleet_software:
        token = (item or "").strip().lower()
        if not token:
            continue
        if token in text:
            return True
        if any(token in p or p in token for p in products_lower):
            return True
    return False


def classify(vuln: Vulnerability, fleet_software: Iterable[str]) -> Vulnerability:
    vuln.category = classify_category(vuln)
    vuln.severity_tier = severity_tier(vuln.cvss_score)
    vuln.fleet_match = fleet_match(vuln, fleet_software)
    return vuln


def wants_immediate_telegram(vuln: Vulnerability) -> bool:
    """critical/high always; any fleet_match; medium/low/unknown only if fleet."""
    if vuln.fleet_match:
        return True
    return vuln.severity_tier in {"critical", "high"}


def wants_email(vuln: Vulnerability, email_cvss_threshold: float = 9.0) -> bool:
    """Email when CVSS >= threshold OR confirmed fleet match."""
    if vuln.fleet_match:
        return True
    if vuln.cvss_score is not None and vuln.cvss_score >= email_cvss_threshold:
        return True
    return False
