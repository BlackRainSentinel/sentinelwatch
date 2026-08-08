"""Feed collector normalization (offline, no network)."""

from __future__ import annotations

from sentinelwatch.collectors.feed import FeedCollector
from sentinelwatch.models import Vulnerability


SAMPLE_ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Test</title>
  <entry>
    <id>tag:example,2024:1</id>
    <title>Security fix for CVE-2024-1234 in Exim</title>
    <link href="https://example.test/1"/>
    <updated>2024-03-01T12:00:00Z</updated>
    <summary>Patch released.</summary>
  </entry>
  <entry>
    <id>tag:example,2024:2</id>
    <title>Marketing: new pricing</title>
    <link href="https://example.test/2"/>
    <updated>2024-03-02T12:00:00Z</updated>
    <summary>Buy more stuff.</summary>
  </entry>
</feed>
"""


def test_feed_filters_and_normalizes(monkeypatch) -> None:
    class FakeResp:
        text = SAMPLE_ATOM

    monkeypatch.setattr(
        "sentinelwatch.collectors.feed.http_get",
        lambda url: FakeResp(),
    )

    c = FeedCollector(
        source="exim_test",
        url="https://example.test/feed",
        include_keywords=["security", "cve"],
        default_products=["exim"],
    )
    items = c.collect()
    assert len(items) == 1
    v = items[0]
    assert isinstance(v, Vulnerability)
    assert v.source == "exim_test"
    assert v.external_id == "tag:example,2024:1"
    assert "CVE-2024-1234" in v.affected_products
    assert v.cvss_score is None  # RSS has no CVSS
    assert v.url == "https://example.test/1"
