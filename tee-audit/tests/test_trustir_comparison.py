"""Tests for the TrustIR vs tee-audit comparison module (US-011)."""

from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.comparison import (
    build_comparison,
    map_family,
    parse_existing_report,
    write_comparison_md,
)

_REPORT = """# Report
## Executive Summary
text
## TEE Usage Problems
### [HIGH] IV-INV-06: SGX SIM mode default with fake attestation [Configuration Integrity] (incorrect_usage) (CWE-1188)
**Root Cause**: x
**Confidence**: Likely | **Invariant**: INV-06 | **Tier**: core
### [MEDIUM] IV-INV-01: Missing semantic validation on host protobuf inputs [Trust Boundary Flow] (incorrect_usage)
**Confidence**: Weak | **Invariant**: INV-01
## Positive Guards (Confirmed Security Controls)
### PG-INV-10: Encrypted request/response with enclave validation
desc
## Dismissed Findings
### ~~IV-INV-09: something~~
- **Original Severity**: Low
- reason
"""


def test_parse_existing_report(tmp_path: Path) -> None:
    p = tmp_path / "r.md"
    p.write_text(_REPORT, encoding="utf-8")
    rep = parse_existing_report(p)
    assert rep["counts"]["active"] == 2
    assert rep["counts"]["positive_guards"] == 1
    assert rep["counts"]["dismissed"] == 1
    ids = {f["id"] for f in rep["active_findings"]}
    assert ids == {"IV-INV-06", "IV-INV-01"}
    by_id = {f["id"]: f for f in rep["active_findings"]}
    assert by_id["IV-INV-06"]["severity"] == "HIGH"
    assert by_id["IV-INV-06"]["confidence"] == "Likely"
    assert by_id["IV-INV-06"]["family"] == "Config"
    assert by_id["IV-INV-01"]["family"] == "Flow"
    assert by_id["IV-INV-01"]["confidence"] == "Weak"


def test_map_family() -> None:
    from tee_audit.trustir.models import TaxonomyFamily

    assert map_family("Configuration Integrity") == TaxonomyFamily.CONFIG
    assert map_family("Trust Boundary Flow") == TaxonomyFamily.FLOW
    assert map_family("Binding Weakness") == TaxonomyFamily.BINDING
    assert map_family("Unknown Thing") is None


def test_build_comparison_corroborated() -> None:
    existing = {
        "active_findings": [
            {"id": "IV-INV-06", "severity": "HIGH", "confidence": "Likely",
             "family": "Config", "family_label": "Configuration Integrity"},
        ],
        "counts": {"active": 1, "positive_guards": 0, "dismissed": 0},
    }
    trustir = [
        {"twe_id": "TWE-CONFIG-001", "family": "Config", "status": "confirmed"},
    ]
    cmp = build_comparison("proj", trustir, existing)
    assert cmp["delta_rows"][0]["trustir_status"] == "confirmed"
    assert "Corroborated" in cmp["delta_rows"][0]["refinement"]


def test_build_comparison_not_reexamined() -> None:
    existing = {
        "active_findings": [
            {"id": "IV-INV-01", "severity": "MEDIUM", "confidence": "Weak",
             "family": "Flow", "family_label": "Trust Boundary Flow"},
        ],
        "counts": {"active": 1, "positive_guards": 0, "dismissed": 0},
    }
    cmp = build_comparison("proj", [], existing)
    assert cmp["delta_rows"][0]["trustir_status"] == "not_reexamined"


def test_write_comparison_md(tmp_path: Path) -> None:
    existing = {
        "active_findings": [
            {"id": "IV-INV-06", "severity": "HIGH", "confidence": "Likely",
             "family": "Config", "family_label": "Configuration Integrity"},
        ],
        "counts": {"active": 1, "positive_guards": 2, "dismissed": 3},
    }
    trustir = [{"twe_id": "TWE-CONFIG-001", "family": "Config", "status": "confirmed"}]
    cmp = build_comparison("fabric-private-chaincode", trustir, existing)
    out = write_comparison_md(cmp, tmp_path / "c" / "comparison.md")
    text = out.read_text()
    assert "fabric-private-chaincode" in text
    assert "Per-finding reconciliation" in text
    assert "IV-INV-06" in text
    assert "positive guards | 2" in text
    assert "dismissed (FP) | 3" in text
