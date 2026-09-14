"""KEV + scoring integration."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelwatch.classifier import classify, wants_immediate_telegram
from sentinelwatch.collectors.kev import KevCollector
from sentinelwatch.models import Vulnerability
from sentinelwatch.taxonomy import PRODUCTS


SAMPLE_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-4577",
            "vendorProject": "PHP",
            "product": "PHP",
            "vulnerabilityName": "PHP CGI Argument Injection",
            "dateAdded": "2024-06-12",
            "shortDescription": "RCE",
            "requiredAction": "Apply updates",
            "dueDate": "2024-07-03",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://www.php.net/",
            "cwes": [],
        },
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Windows",
            "dateAdded": "2024-01-01",
            "shortDescription": "Unrelated",
            "requiredAction": "x",
            "dueDate": "2024-02-01",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
        },
    ]
}


def test_kev_filters_to_taxonomy(monkeypatch) -> None:
    class FakeResp:
        def json(self):
            return SAMPLE_KEV

    monkeypatch.setattr(
        "sentinelwatch.collectors.kev.http_get",
        lambda url, timeout=90.0, **kw: FakeResp(),
    )
    items = KevCollector(taxonomy=list(PRODUCTS)).collect()
    assert {i.external_id for i in items} == {"CVE-2024-4577"}


def test_thread_key_precve_to_cve() -> None:
    v = classify(
        Vulnerability(
            external_id="oss-1",
            source="seclists_oss_sec",
            title="Exim possible RCE discussion",
            description="pre disclosure",
            cvss_score=None,
            reported_severity=None,
            affected_products=["exim:exim"],
            cve_ids=[],
            published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
            url="https://example.test",
            source_tier=2,
        ),
        PRODUCTS,
    )
    assert v.thread_key.startswith("precve:")
    assert wants_immediate_telegram(v) or v.product_match
