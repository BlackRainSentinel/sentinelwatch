"""Shared collector contract and HTTP helpers."""

from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional

import httpx

from sentinelwatch.models import Vulnerability

log = logging.getLogger(__name__)

USER_AGENT = "SentinelWatch/1.0 (+https://github.com/BlackRainSentinel/sentinelwatch)"


class Collector(ABC):
    """Every source implements collect() -> list[Vulnerability]. Nothing else."""

    name: str = "base"

    @abstractmethod
    def collect(self) -> list[Vulnerability]:
        raise NotImplementedError


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 60.0,
) -> httpx.Response:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=hdrs, params=params)
        resp.raise_for_status()
        return resp


def stable_id(*parts: str, length: int = 16) -> str:
    raw = "|".join(p.strip() for p in parts if p)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


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
    # ISO-ish
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
