"""Offline collector tests + changelog plaintext fixture."""

from __future__ import annotations

import pytest

from sentinelwatch.collectors.changelog import ChangelogCollector
from sentinelwatch.collectors.feed import FeedCollector
from sentinelwatch.collectors.wordfence import WordfenceCollector


SAMPLE_ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:example,2024:1</id>
    <title>Security fix for CVE-2024-1234 in Exim</title>
    <link href="https://example.test/1"/>
    <updated>2024-03-01T12:00:00Z</updated>
    <summary>Patch released for versions before 4.97.</summary>
  </entry>
</feed>
"""

CSF_TXT = """
14.20
Security: fix privilege issue CVE-2024-9999 in lfd
Other: UI tweak

14.19
Feature: something boring
"""


def test_feed_cve_field(monkeypatch) -> None:
    class FakeResp:
        text = SAMPLE_ATOM

    monkeypatch.setattr(
        "sentinelwatch.collectors.feed.http_get", lambda url, **kw: FakeResp()
    )
    items = FeedCollector(
        "exim_test",
        "https://example.test/feed",
        source_tier=1,
        include_keywords=["security"],
        default_products=["exim:exim"],
    ).collect()
    assert items[0].cve_ids == ["CVE-2024-1234"]
    assert "CVE-2024-1234" not in items[0].affected_products


def test_wordfence_requires_key() -> None:
    with pytest.raises(RuntimeError, match="WORDFENCE_API_KEY"):
        WordfenceCollector(api_key="").collect()


def test_csf_plaintext_changelog(monkeypatch) -> None:
    class FakeResp:
        text = CSF_TXT
        headers = {"content-type": "text/plain"}

    monkeypatch.setattr(
        "sentinelwatch.collectors.changelog.http_get",
        lambda url, **kw: FakeResp(),
    )
    c = ChangelogCollector(
        "csf",
        "https://example.test/changelog.txt",
        default_products=["configserver:csf"],
        include_keywords=["security", "cve", "lfd"],
    )
    items = c.collect()
    assert any("CVE-2024-9999" in i.cve_ids for i in items)
    assert all("configserver:csf" in i.affected_products for i in items)
