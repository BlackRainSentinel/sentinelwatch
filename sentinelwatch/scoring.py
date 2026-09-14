"""
Alert scoring — ranks findings so Telegram stays usable.

Score is 0–100. Delivery thresholds use this plus golden-rule overrides.
"""

from __future__ import annotations

from sentinelwatch.impact import max_product_criticality
from sentinelwatch.models import Vulnerability


def compute_alert_score(vuln: Vulnerability) -> float:
    score = 0.0

    # Exploitability / authority
    if vuln.in_kev or vuln.in_hosting_kev:
        score += 40
    if vuln.always_alert:
        score += 10

    # CVSS
    if vuln.cvss_score is not None:
        score += min(30.0, float(vuln.cvss_score) * 3.0)
    elif vuln.severity_tier == "unknown":
        # Pre-CVE / RSS: small base if product matched
        score += 8 if vuln.product_match else 2

    # Source trust
    score += {1: 12, 2: 8, 3: 3}.get(int(vuln.source_tier or 3), 3)

    # Product criticality on shared hosting (0-10 → 0-15)
    score += max_product_criticality(vuln.matched_products) * 1.5

    # Blast radius
    score += {"critical": 10, "elevated": 5, "normal": 0}.get(vuln.blast_radius, 0)

    # Version applicability dampener (KEV never dampened)
    if not vuln.version_applicable and not (vuln.in_kev or vuln.in_hosting_kev):
        score *= 0.35

    # WordPress plugin noise dampener unless high/critical or KEV
    if (
        vuln.category == "wordpress"
        and vuln.source_tier >= 3
        and vuln.severity_tier in {"medium", "low", "unknown"}
        and not (vuln.in_kev or vuln.in_hosting_kev)
    ):
        score *= 0.5

    return round(min(100.0, score), 1)


def pick_channel(vuln: Vulnerability) -> str:
    """Split streams: critical-now / wordpress / digest."""
    if vuln.category == "wordpress" and not (
        vuln.in_kev or vuln.in_hosting_kev or vuln.severity_tier in {"critical", "high"}
    ):
        return "wordpress"
    if (
        vuln.always_alert
        or vuln.in_kev
        or vuln.in_hosting_kev
        or vuln.alert_score >= 55
        or (
            vuln.severity_tier in {"critical", "high"}
            and vuln.product_match
            and vuln.version_applicable
        )
    ):
        return "critical"
    return "digest"


def wants_immediate_telegram(vuln: Vulnerability, min_score: float = 55.0) -> bool:
    if vuln.in_kev or vuln.in_hosting_kev or vuln.always_alert:
        return True
    if not vuln.version_applicable and not vuln.always_alert:
        return False
    if vuln.channel == "wordpress":
        return False  # wordpress channel is batched unless escalated above
    if vuln.channel == "critical":
        return True
    return vuln.alert_score >= min_score and vuln.product_match


def wants_email(
    vuln: Vulnerability,
    email_cvss_threshold: float = 9.0,
    min_score: float = 70.0,
) -> bool:
    if vuln.in_kev or vuln.in_hosting_kev or vuln.always_alert:
        return True
    if not vuln.version_applicable:
        return False
    if vuln.cvss_score is not None and vuln.cvss_score >= email_cvss_threshold:
        return True
    return vuln.alert_score >= min_score
