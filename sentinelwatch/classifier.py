"""
Structured product matching, version applicability, golden rule (v3).
"""

from __future__ import annotations

import re
from typing import Iterable

from sentinelwatch.impact import annotate_impact
from sentinelwatch.models import Vulnerability
from sentinelwatch.scoring import compute_alert_score, pick_channel
from sentinelwatch.taxonomy import ProductSpec, PRODUCTS, load_taxonomy
from sentinelwatch.versions import check_applicability, extract_version_hints


_AMBIGUOUS_ALIASES = frozenset({"php", "named", "csf", "lfd", "pdns", "spamd"})


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


def _word_boundary_re(alias: str) -> re.Pattern[str]:
    parts = [re.escape(p) for p in alias.strip().split() if p]
    if not parts:
        return re.compile(r"(?!)")
    body = r"[\s\-_/]*".join(parts)
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE)


def _haystack(vuln: Vulnerability) -> str:
    return " ".join(
        [
            vuln.title or "",
            vuln.description or "",
            " ".join(vuln.affected_products or []),
            " ".join(vuln.matched_products or []),
        ]
    )


def _parse_cpe_pair(token: str) -> tuple[str, str] | None:
    t = (token or "").strip().lower()
    if not t:
        return None
    if t.startswith("cpe:"):
        parts = t.split(":")
        if len(parts) >= 5:
            return parts[3], parts[4]
        return None
    if ":" in t and not t.upper().startswith("CVE-"):
        vendor, product = t.split(":", 1)
        if vendor and product and not product.upper().startswith("CVE-"):
            return vendor, product
    return None


def match_products(
    vuln: Vulnerability,
    taxonomy: Iterable[ProductSpec] | None = None,
) -> list[ProductSpec]:
    specs = list(taxonomy) if taxonomy is not None else list(PRODUCTS)
    text = _haystack(vuln)

    cpe_pairs: set[tuple[str, str]] = set()
    for token in vuln.affected_products or []:
        pair = _parse_cpe_pair(token)
        if pair:
            cpe_pairs.add(pair)

    matched: list[ProductSpec] = []
    seen: set[str] = set()

    for spec in specs:
        hit = False
        for cv, cp in spec.cpe_pairs:
            if (cv.lower(), cp.lower()) in cpe_pairs:
                hit = True
                break
            for pv, pp in cpe_pairs:
                if pp == cp.lower() and (
                    pv == cv.lower() or pv == spec.vendor.lower()
                ):
                    hit = True
                    break
            if hit:
                break

        if not hit:
            aliases = sorted(spec.aliases, key=len, reverse=True)
            if spec.id == "php:php":
                aliases = list(aliases) + ["php"]
            for alias in aliases:
                if not alias:
                    continue
                if not _word_boundary_re(alias).search(text):
                    continue
                if alias.lower() in {"named", "csf", "lfd", "pdns", "spamd"}:
                    hints = ("dns", "bind", "firewall", "configserver", "mail", "spam")
                    products_l = " ".join(vuln.affected_products or []).lower()
                    if (
                        any(_word_boundary_re(h).search(text) for h in hints)
                        or alias.lower() in products_l
                        or (
                            alias.lower() in {"csf", "lfd"}
                            and _word_boundary_re("configserver").search(text)
                        )
                    ):
                        hit = True
                else:
                    hit = True
                if hit:
                    break

        if hit and spec.id not in seen:
            seen.add(spec.id)
            matched.append(spec)

    return matched


def apply_golden_rule(vuln: Vulnerability) -> None:
    if vuln.in_kev or vuln.in_hosting_kev:
        vuln.always_alert = True
        return
    if vuln.source == "cisa_kev":
        vuln.always_alert = True
        return
    if vuln.source_tier == 1 and vuln.product_match:
        vuln.always_alert = True


def classify(
    vuln: Vulnerability,
    taxonomy: Iterable[ProductSpec] | None = None,
    kev_cves: set[str] | None = None,
    hosting_kev: set[str] | None = None,
    fleet_versions: dict[str, list[str]] | None = None,
) -> Vulnerability:
    specs = list(taxonomy) if taxonomy is not None else list(PRODUCTS)

    cves = {c.upper() for c in (vuln.cve_ids or []) if c}
    for token in list(vuln.affected_products or []):
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", token or "", flags=re.I):
            cves.add(token.upper())
            vuln.affected_products = [
                p
                for p in vuln.affected_products
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", p or "", flags=re.I)
            ]
    vuln.cve_ids = sorted(cves)

    if kev_cves and any(c in kev_cves for c in vuln.cve_ids):
        vuln.in_kev = True
    if hosting_kev and any(c in hosting_kev for c in vuln.cve_ids):
        vuln.in_hosting_kev = True

    matched = match_products(vuln, specs)
    vuln.matched_products = [m.id for m in matched]
    vuln.product_match = bool(matched)
    vuln.category = matched[0].category if matched else "other"
    vuln.severity_tier = severity_tier(vuln.cvss_score)

    # Version hints
    if not vuln.affected_versions:
        vuln.affected_versions = extract_version_hints(
            f"{vuln.title} {vuln.description}"
        )
    applicable, unknown = check_applicability(
        vuln.matched_products,
        vuln.affected_versions,
        fleet_versions or {},
    )
    vuln.version_applicable = applicable
    vuln.version_unknown = unknown

    # Pre-CVE thread key: prefer CVE, else stable product+title slug
    if vuln.cve_ids:
        vuln.thread_key = vuln.cve_ids[0]
    elif vuln.matched_products:
        vuln.thread_key = f"precve:{vuln.matched_products[0]}:{vuln.external_id[:32]}"
    else:
        vuln.thread_key = f"precve:{vuln.source}:{vuln.external_id[:32]}"

    apply_golden_rule(vuln)
    # Version-non-applicable findings lose always_alert UNLESS KEV/hosting-KEV
    if (
        not vuln.version_applicable
        and not vuln.in_kev
        and not vuln.in_hosting_kev
        and vuln.always_alert
        and vuln.source_tier == 1
    ):
        # Keep always_alert for KEV only; Tier-1 non-applicable goes to digest
        vuln.always_alert = False

    annotate_impact(vuln)
    vuln.alert_score = compute_alert_score(vuln)
    vuln.channel = pick_channel(vuln)
    return vuln


# Re-export delivery predicates from scoring for backward-compatible imports
from sentinelwatch.scoring import wants_email, wants_immediate_telegram  # noqa: E402


def build_taxonomy_from_config(config: dict | None) -> tuple[ProductSpec, ...]:
    extra = (config or {}).get("taxonomy_extra") or []
    return load_taxonomy(extra if isinstance(extra, list) else [])
