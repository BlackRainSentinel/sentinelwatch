"""Shared collector contract, HTTP with retries, helpers."""

from __future__ import annotations

import hashlib
import logging
import random
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional

import httpx

from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

USER_AGENT = (
    "SentinelWatch/3.0 (+https://github.com/BlackRainSentinel/sentinelwatch)"
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class Collector(ABC):
    name: str = "base"
    source_tier: int = 3
    # schedule class: "fast" (Tier1/oss-sec) or "slow" (tier3 heavy)
    schedule: str = "fast"

    @abstractmethod
    def collect(self) -> list[Vulnerability]:
        raise NotImplementedError


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 60.0,
    retries: int = 3,
) -> httpx.Response:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=hdrs, params=params)
                if resp.status_code in {429, 500, 502, 503, 504} and attempt < retries - 1:
                    delay = (2 ** attempt) + random.uniform(0, 0.5)
                    log.warning(
                        "HTTP %s for %s — retry in %.1fs",
                        resp.status_code,
                        url,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                resp.raise_for_status()
                return resp
        except Exception as exc:
            last_exc = exc
            if attempt >= retries - 1:
                break
            delay = (2 ** attempt) + random.uniform(0, 0.5)
            log.warning("Request error for %s: %s — retry in %.1fs", url, exc, delay)
            time.sleep(delay)
    assert last_exc is not None
    raise last_exc


def stable_id(*parts: str, length: int = 16) -> str:
    raw = "|".join(p.strip() for p in parts if p)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]


def extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text or "")})


def parse_date(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError, IndexError):
        return None


__all__ = [
    "Collector",
    "USER_AGENT",
    "http_get",
    "stable_id",
    "extract_cves",
    "parse_date",
    "Vulnerability",
]
