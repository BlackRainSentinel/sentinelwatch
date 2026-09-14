"""CVSS severity emblem mapping and assets."""

from __future__ import annotations

from sentinelwatch.severity_emblem import (
    SeverityState,
    cvss_to_state,
    export_all,
    resolve_assets,
    select_assessment,
)


def test_cvss_boundaries() -> None:
    assert cvss_to_state(0.0) == SeverityState.NONE
    assert cvss_to_state(0.1) == SeverityState.LOW
    assert cvss_to_state(3.9) == SeverityState.LOW
    assert cvss_to_state(4.0) == SeverityState.MEDIUM
    assert cvss_to_state(6.9) == SeverityState.MEDIUM
    assert cvss_to_state(7.0) == SeverityState.HIGH
    assert cvss_to_state(8.9) == SeverityState.HIGH
    assert cvss_to_state(9.0) == SeverityState.CRITICAL
    assert cvss_to_state(9.8) == SeverityState.CRITICAL
    assert cvss_to_state(10.0) == SeverityState.CRITICAL


def test_invalid_scores() -> None:
    assert cvss_to_state(None) == SeverityState.UNKNOWN
    assert cvss_to_state("") == SeverityState.UNKNOWN
    assert cvss_to_state("nope") == SeverityState.UNKNOWN
    assert cvss_to_state(-1) == SeverityState.UNKNOWN
    assert cvss_to_state(11) == SeverityState.UNKNOWN


def test_zero_is_none_not_secure_claim() -> None:
    # Zero maps to NONE label — not a "secure" marketing state
    assert cvss_to_state(0) == SeverityState.NONE


def test_multi_assessment_prefers_nvd() -> None:
    chosen = select_assessment(
        [
            {"score": 7.5, "source": "vendor"},
            {"score": 9.8, "source": "nvd"},
        ]
    )
    assert chosen is not None
    assert float(chosen["score"]) == 9.8
    assert chosen["source"] == "nvd"


def test_assets_exist() -> None:
    for score in (0.0, 2.0, 5.0, 8.0, 9.8, None):
        state, gif, png = resolve_assets(score)
        assert gif.is_file(), gif
        assert png.is_file(), png
        assert gif.stat().st_size > 1000
        assert png.stat().st_size > 1000
