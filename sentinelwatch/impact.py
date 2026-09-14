"""
Hosting-specific impact notes and blast-radius scoring hints.

This is the domain moat: shared-hosting operator context, not generic CVE text.
"""

from __future__ import annotations

from sentinelwatch.models import Vulnerability


# Product criticality on a multi-tenant shared host (0-10)
PRODUCT_CRITICALITY: dict[str, int] = {
    "cpanel:cpanel": 10,
    "directadmin:directadmin": 10,
    "cloudlinux:imunify360": 10,  # security product compromise
    "configserver:csf": 9,
    "exim:exim": 9,
    "dovecot:dovecot": 8,
    "php:php": 9,
    "litespeed:litespeed": 8,
    "apache:http_server": 8,
    "mariadb:mariadb": 7,
    "oracle:mysql": 7,
    "openssl:openssl": 8,
    "cisco:clamav": 7,
    "cloudlinux:cloudlinux": 8,
    "pureftpd:pure-ftpd": 6,
    "powerdns:powerdns": 6,
    "isc:bind": 6,
    "jetbackup:jetbackup": 7,
    "mongodb:mongodb": 5,
    "wordpress:wordpress": 5,
    "apache:spamassassin": 4,
    "almalinux:almalinux": 6,
    "canonical:ubuntu_linux": 5,
    "debian:debian_linux": 5,
    "redhat:enterprise_linux": 5,
    "gnu:glibc": 7,
    "linux:kernel": 7,
}

IMPACT_NOTES: dict[str, str] = {
    "cpanel:cpanel": (
        "Panel RCE/auth bypass = full multi-tenant compromise. "
        "Check WHM version, EasyApache PHP builds, and WP Toolkit."
    ),
    "directadmin:directadmin": (
        "DirectAdmin privilege issues often lead to reseller→root paths. "
        "Verify DA version and custombuild PHP/Apache/LiteSpeed builds."
    ),
    "exim:exim": (
        "Exim on shared hosts is internet-facing and historically wormed. "
        "Treat pre-CVE oss-security reports as urgent; verify ACL/local scans."
    ),
    "php:php": (
        "PHP-FPM pools serve many tenants. Map to ea-php*/alt-php*/php-fpm* "
        "versions before dismissing; CageFS does not fix interpreter bugs."
    ),
    "cloudlinux:imunify360": (
        "SECURITY PRODUCT TARGET — if Imunify/WebShield/Aibolit is vulnerable, "
        "raise severity mentally even when CVSS looks medium."
    ),
    "configserver:csf": (
        "CSF/lfd compromise weakens host firewall and login detection. "
        "Patch CSF promptly; verify lfd is running after upgrade."
    ),
    "cisco:clamav": (
        "ClamAV bugs can be reached via mail/upload scanning paths on shared hosts."
    ),
    "litespeed:litespeed": (
        "LiteSpeed/OpenLiteSpeed sits in front of all sites — "
        "prefer vendor advisory over waiting for NVD."
    ),
    "openssl:openssl": (
        "Affects TLS for panel, mail, and sites. Plan staged restarts of "
        "lshttpd/httpd/exim/dovecot after library upgrade."
    ),
    "wordpress:wordpress": (
        "Core/plugin issues are noisy; prioritize auth bypass / RCE / "
        "privilege escalation over low XSS in obscure plugins."
    ),
    "jetbackup:jetbackup": (
        "Backup agents hold privileged filesystem access and DB credentials. "
        "Treat JetBackup CVEs as host-level risk."
    ),
}


def blast_radius_for(matched_products: list[str], category: str) -> str:
    """critical | elevated | normal based on multi-tenant defaults."""
    if any(p in matched_products for p in (
        "cloudlinux:imunify360",
        "configserver:csf",
        "cpanel:cpanel",
        "directadmin:directadmin",
        "exim:exim",
    )):
        return "critical"
    if category in {"panel", "mail", "security", "php", "webserver"}:
        return "elevated"
    max_c = max((PRODUCT_CRITICALITY.get(p, 3) for p in matched_products), default=3)
    if max_c >= 8:
        return "elevated"
    return "normal"


def impact_note_for(matched_products: list[str]) -> str:
    notes = [IMPACT_NOTES[p] for p in matched_products if p in IMPACT_NOTES]
    return " ".join(notes[:2])


def max_product_criticality(matched_products: list[str]) -> int:
    if not matched_products:
        return 3
    return max(PRODUCT_CRITICALITY.get(p, 3) for p in matched_products)


def annotate_impact(vuln: Vulnerability) -> Vulnerability:
    vuln.blast_radius = blast_radius_for(vuln.matched_products, vuln.category)
    vuln.impact_note = impact_note_for(vuln.matched_products)
    return vuln
