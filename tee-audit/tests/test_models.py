"""Tests for data models."""

from __future__ import annotations

import pytest

from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant, InvariantFamily
from tee_audit.models.finding import (
    CodeLocation,
    Confidence,
    Finding,
    Severity,
    TrustPathTier,
)
from tee_audit.models.triage import Grade, GradedFinding, PositiveGuard
from tee_audit.models.unknown import Unknown
from tee_audit.models.report import DashboardEntry, Report


class TestFingerprint:
    def test_basic_construction(self, sample_fingerprint: Fingerprint):
        assert sample_fingerprint.repo_root == "/tmp/test-repo"
        assert "rs" in sample_fingerprint.top_extensions
        assert "go" in sample_fingerprint.codeql_languages

    def test_empty_fingerprint(self):
        fp = Fingerprint(
            repo_root="/tmp/empty",
            top_extensions={},
            codeql_languages=[],
            tee_platforms={},
            web3_roles={},
            trust_artifacts={},
            build_flags={},
            critical_paths=[],
        )
        assert fp.repo_root == "/tmp/empty"
        assert fp.codeql_languages == []

    def test_json_round_trip(self, sample_fingerprint: Fingerprint):
        json_str = sample_fingerprint.model_dump_json()
        restored = Fingerprint.model_validate_json(json_str)
        assert restored == sample_fingerprint


class TestInvariant:
    def test_basic_construction(self):
        inv = Invariant(
            id="INV-01",
            description="Test invariant",
            trust_path="host → enclave",
            family=InvariantFamily.GUARD,
            sources=["src"],
            sinks=["sink"],
            guards=["guard"],
            failure_modes=["fail"],
            codeql_expressible=True,
        )
        assert inv.family == InvariantFamily.GUARD
        assert inv.codeql_expressible is True

    def test_all_families(self):
        for family in InvariantFamily:
            inv = Invariant(
                id="INV-TEST",
                description="x",
                trust_path="a → b",
                family=family,
                sources=[],
                sinks=[],
                guards=[],
                failure_modes=[],
                codeql_expressible=False,
            )
            assert inv.family == family

    def test_invalid_family_raises(self):
        with pytest.raises(ValueError):
            InvariantFamily("nonexistent")


class TestFinding:
    def test_basic_construction(self):
        f = Finding(
            id="V-01",
            invariant_id="INV-01",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            title="Test finding",
            attack_path=["step 1", "step 2"],
            code_locations=[CodeLocation(file="src/main.rs", line=10)],
            remediation="Fix it",
            trust_path_tier=TrustPathTier.CORE,
        )
        assert f.severity == Severity.HIGH
        assert len(f.attack_path) == 2
        assert f.code_locations[0].file == "src/main.rs"

    def test_optional_snippet(self):
        loc = CodeLocation(file="a.rs")
        assert loc.line is None
        assert loc.snippet is None

    def test_severity_values(self):
        expected = {"Critical", "High", "Medium", "Low", "Info"}
        assert {s.value for s in Severity} == expected

    def test_confidence_values(self):
        expected = {"Confirmed", "Likely", "Weak", "NeedsManual"}
        assert {c.value for c in Confidence} == expected

    def test_trust_path_tier_values(self):
        expected = {"core", "adjacent", "peripheral"}
        assert {t.value for t in TrustPathTier} == expected


class TestTriage:
    def test_graded_finding(self):
        gf = GradedFinding(
            sarif_result_id="SARIF-001",
            invariant_id="INV-01",
            grade=Grade.LIKELY_ISSUE,
            confidence=Confidence.LIKELY,
            code_location="src/main.rs:10",
        )
        assert gf.grade == Grade.LIKELY_ISSUE
        assert gf.snippet is None

    def test_positive_guard(self):
        pg = PositiveGuard(
            id="PG-01",
            invariant_refs=["INV-01"],
            trust_path_tier="core",
            description="Input validation present",
            code_evidence="src/validate.rs:5",
            completeness_status="complete",
        )
        assert pg.completeness_status == "complete"
        assert len(pg.invariant_refs) == 1


class TestUnknown:
    def test_basic_construction(self):
        u = Unknown(
            id="U-01",
            what_was_checked="Key boundary flow",
            why_uncertain="Cannot trace across FFI boundary",
            recommended_steps=["Manual review of FFI layer"],
        )
        assert u.why_uncertain.startswith("Cannot")


class TestReport:
    def test_basic_construction(self, sample_fingerprint, sample_invariants):
        report = Report(
            project_name="test-project",
            fingerprint=sample_fingerprint,
            invariants=sample_invariants,
            findings=[],
            positive_guards=[],
            unknowns=[],
            dashboard=[
                DashboardEntry(severity=Severity.HIGH, trust_path_tier=TrustPathTier.CORE, count=2),
            ],
            executive_summary="Test summary.",
        )
        assert report.project_name == "test-project"
        assert len(report.dashboard) == 1
        assert report.dashboard[0].count == 2

    def test_minimal_report(self):
        report = Report(project_name="minimal")
        assert report.fingerprint is None
        assert report.findings == []
        assert report.executive_summary == ""
