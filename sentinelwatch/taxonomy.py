"""
Curated vendor:product taxonomy for the hosting / control-panel ecosystem.

Adding a tracked product = one ProductSpec entry (or a config override),
not a classifier code change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductSpec:
    """One tracked product in the hosting stack."""

    id: str  # canonical "vendor:product"
    vendor: str
    product: str
    category: str
    # Word-boundary aliases matched against free text (case-insensitive)
    aliases: tuple[str, ...]
    # CPE 2.3 vendor/product pairs when structured data is present
    cpe_pairs: tuple[tuple[str, str], ...] = ()


# Authoritative starting inventory from the v2 spec.
PRODUCTS: tuple[ProductSpec, ...] = (
    # --- Control panels -------------------------------------------------
    ProductSpec(
        id="cpanel:cpanel",
        vendor="cpanel",
        product="cpanel",
        category="panel",
        aliases=("cpanel", "whm", "wp squared", "wp-toolkit", "wp toolkit"),
        cpe_pairs=(("cpanel", "cpanel"), ("cpanel", "whm")),
    ),
    ProductSpec(
        id="directadmin:directadmin",
        vendor="directadmin",
        product="directadmin",
        category="panel",
        aliases=("directadmin", "direct admin"),
        cpe_pairs=(("jbmc-software", "directadmin"), ("directadmin", "directadmin")),
    ),
    # --- Web servers ----------------------------------------------------
    ProductSpec(
        id="litespeed:litespeed",
        vendor="litespeed",
        product="litespeed",
        category="webserver",
        aliases=("litespeed", "openlitespeed", "lshttpd"),
        cpe_pairs=(
            ("litespeedtech", "litespeed_web_server"),
            ("litespeedtech", "openlitespeed"),
            ("litespeed", "litespeed"),
        ),
    ),
    ProductSpec(
        id="apache:http_server",
        vendor="apache",
        product="http_server",
        category="webserver",
        aliases=("apache http server", "apache httpd", "apache2", "httpd"),
        cpe_pairs=(("apache", "http_server"), ("apache", "httpd")),
    ),
    # --- Databases ------------------------------------------------------
    ProductSpec(
        id="mariadb:mariadb",
        vendor="mariadb",
        product="mariadb",
        category="database",
        aliases=("mariadb",),
        cpe_pairs=(("mariadb", "mariadb"),),
    ),
    ProductSpec(
        id="oracle:mysql",
        vendor="oracle",
        product="mysql",
        category="database",
        aliases=("mysql", "mysqld"),
        cpe_pairs=(("oracle", "mysql"), ("mysql", "mysql")),
    ),
    ProductSpec(
        id="mongodb:mongodb",
        vendor="mongodb",
        product="mongodb",
        category="database",
        aliases=("mongodb", "mongo db", "jetmongod"),
        cpe_pairs=(("mongodb", "mongodb"),),
    ),
    # --- Mail -----------------------------------------------------------
    ProductSpec(
        id="exim:exim",
        vendor="exim",
        product="exim",
        category="mail",
        aliases=("exim",),
        cpe_pairs=(("exim", "exim"),),
    ),
    ProductSpec(
        id="dovecot:dovecot",
        vendor="dovecot",
        product="dovecot",
        category="mail",
        aliases=("dovecot",),
        cpe_pairs=(("dovecot", "dovecot"),),
    ),
    ProductSpec(
        id="apache:spamassassin",
        vendor="apache",
        product="spamassassin",
        category="mail",
        aliases=("spamassassin", "spamd"),
        cpe_pairs=(("apache", "spamassassin"),),
    ),
    # --- DNS ------------------------------------------------------------
    ProductSpec(
        id="powerdns:powerdns",
        vendor="powerdns",
        product="powerdns",
        category="dns",
        aliases=("powerdns", "pdns"),
        cpe_pairs=(("powerdns", "authoritative_server"), ("powerdns", "recursor")),
    ),
    ProductSpec(
        id="isc:bind",
        vendor="isc",
        product="bind",
        category="dns",
        aliases=("bind9", "isc bind", "named"),
        cpe_pairs=(("isc", "bind"),),
    ),
    # --- FTP ------------------------------------------------------------
    ProductSpec(
        id="pureftpd:pure-ftpd",
        vendor="pureftpd",
        product="pure-ftpd",
        category="ftp",
        aliases=("pure-ftpd", "pureftpd", "pure ftpd"),
        cpe_pairs=(("pureftpd", "pure-ftpd"), ("pureftpd", "pureftpd")),
    ),
    # --- Security stack -------------------------------------------------
    ProductSpec(
        id="cloudlinux:imunify360",
        vendor="cloudlinux",
        product="imunify360",
        category="security",
        aliases=("imunify360", "imunify 360", "imunify", "aibolit", "webshield"),
        cpe_pairs=(("cloudlinux", "imunify360"), ("imunify360", "imunify360")),
    ),
    ProductSpec(
        id="cisco:clamav",
        vendor="cisco",
        product="clamav",
        category="security",
        aliases=("clamav", "clamd", "freshclam"),
        cpe_pairs=(("cisco", "clamav"), ("clamav", "clamav")),
    ),
    ProductSpec(
        id="configserver:csf",
        vendor="configserver",
        product="csf",
        category="security",
        aliases=("configserver security", "csf", "lfd"),
        cpe_pairs=(("configserver", "csf"), ("configserver", "lfd")),
    ),
    ProductSpec(
        id="cloudlinux:cloudlinux",
        vendor="cloudlinux",
        product="cloudlinux",
        category="os",
        aliases=("cloudlinux", "cagefs", "lve", "php selector", "ssa-agent"),
        cpe_pairs=(("cloudlinux", "cloudlinux"), ("cloudlinux", "cagefs")),
    ),
    # --- Backup / management --------------------------------------------
    ProductSpec(
        id="jetbackup:jetbackup",
        vendor="jetbackup",
        product="jetbackup",
        category="backup",
        aliases=("jetbackup", "jet backup"),
        cpe_pairs=(("jetapps", "jetbackup"), ("jetbackup", "jetbackup")),
    ),
    # --- PHP ------------------------------------------------------------
    ProductSpec(
        id="php:php",
        vendor="php",
        product="php",
        category="php",
        aliases=("php-fpm", "php fpm", "alt-php", "ea-php"),
        # bare "php" is handled carefully in classifier (word-boundary + context)
        cpe_pairs=(("php", "php"),),
    ),
    # --- WordPress ------------------------------------------------------
    ProductSpec(
        id="wordpress:wordpress",
        vendor="wordpress",
        product="wordpress",
        category="wordpress",
        aliases=("wordpress", "wp-cli", "woocommerce"),
        cpe_pairs=(("wordpress", "wordpress"),),
    ),
    # --- Base OS / crypto -----------------------------------------------
    ProductSpec(
        id="almalinux:almalinux",
        vendor="almalinux",
        product="almalinux",
        category="os",
        aliases=("almalinux", "alma linux"),
        cpe_pairs=(("almalinux", "almalinux"),),
    ),
    ProductSpec(
        id="canonical:ubuntu_linux",
        vendor="canonical",
        product="ubuntu_linux",
        category="os",
        aliases=("ubuntu",),
        cpe_pairs=(("canonical", "ubuntu_linux"),),
    ),
    ProductSpec(
        id="debian:debian_linux",
        vendor="debian",
        product="debian_linux",
        category="os",
        aliases=("debian",),
        cpe_pairs=(("debian", "debian_linux"),),
    ),
    ProductSpec(
        id="redhat:enterprise_linux",
        vendor="redhat",
        product="enterprise_linux",
        category="os",
        aliases=("red hat enterprise linux", "rhel", "centos"),
        cpe_pairs=(("redhat", "enterprise_linux"), ("centos", "centos")),
    ),
    ProductSpec(
        id="openssl:openssl",
        vendor="openssl",
        product="openssl",
        category="os",
        aliases=("openssl",),
        cpe_pairs=(("openssl", "openssl"),),
    ),
    ProductSpec(
        id="gnu:glibc",
        vendor="gnu",
        product="glibc",
        category="os",
        aliases=("glibc", "gnu c library"),
        cpe_pairs=(("gnu", "glibc"),),
    ),
    ProductSpec(
        id="linux:kernel",
        vendor="linux",
        product="kernel",
        category="os",
        aliases=("linux kernel",),
        cpe_pairs=(("linux", "linux_kernel"),),
    ),
)


PRODUCTS_BY_ID: dict[str, ProductSpec] = {p.id: p for p in PRODUCTS}


def load_taxonomy(extra: list[dict] | None = None) -> tuple[ProductSpec, ...]:
    """Merge built-in taxonomy with optional config overlays."""
    items = list(PRODUCTS)
    for raw in extra or []:
        if not isinstance(raw, dict):
            continue
        pid = (raw.get("id") or "").strip()
        if not pid:
            continue
        aliases = tuple(str(a) for a in (raw.get("aliases") or []))
        cpe_raw = raw.get("cpe_pairs") or []
        normalized: list[tuple[str, str]] = []
        for pair in cpe_raw:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                normalized.append((str(pair[0]), str(pair[1])))
        items.append(
            ProductSpec(
                id=pid,
                vendor=str(raw.get("vendor") or pid.split(":")[0]),
                product=str(raw.get("product") or pid.split(":")[-1]),
                category=str(raw.get("category") or "other"),
                aliases=aliases,
                cpe_pairs=tuple(normalized),
            )
        )
    # Later entries with same id override earlier (config wins)
    by_id: dict[str, ProductSpec] = {}
    for p in items:
        by_id[p.id] = p
    return tuple(by_id.values())
