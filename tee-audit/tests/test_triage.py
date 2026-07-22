"""Tests for Stage 5a: Triage."""

from __future__ import annotations

from pathlib import Path

from tee_audit.stages.triage import _classify_confidence, _match_invariant, run_triage
from tee_audit.contracts import Stage5aInput
from tee_audit.models.finding import Confidence
from tee_audit.models.triage import Grade


class TestClassifyConfidence:
    def test_error_message(self):
        grade, conf = _classify_confidence("some-rule", "Critical error in flow")
        assert grade == Grade.LIKELY_ISSUE
        assert conf == Confidence.LIKELY

    def test_warning_message(self):
        grade, conf = _classify_confidence("some-rule", "Warning: potential issue")
        assert grade == Grade.LIKELY_ISSUE

    def test_info_message(self):
        grade, conf = _classify_confidence("some-rule", "Note: informational")
        assert grade == Grade.WEAK_SIGNAL
        assert conf == Confidence.WEAK

    def test_guard_rule_complete(self):
        grade, conf = _classify_confidence(
            "guard-check", "Guard verified complete: present"
        )
        assert grade == Grade.CONFIRMED_ISSUE
        assert conf == Confidence.CONFIRMED

    def test_unknown_defaults_to_agent_validation(self):
        grade, conf = _classify_confidence("unknown-rule", "Something happened")
        assert grade == Grade.NEEDS_MANUAL_VALIDATION
        assert conf == Confidence.NEEDS_MANUAL


class TestMatchInvariant:
    def test_direct_id_match(self, sample_invariants):
        result = _match_invariant("inv-01-something", sample_invariants)
        assert result == "INV-01"

    def test_family_match(self, sample_invariants):
        result = _match_invariant("guard-related-rule", sample_invariants)
        assert result == "INV-01"  # INV-01 is family=GUARD

    def test_binding_family(self, sample_invariants):
        result = _match_invariant("binding-rule", sample_invariants)
        assert result == "INV-02"  # INV-02 is family=BINDING

    def test_unmatched(self, sample_invariants):
        result = _match_invariant("totally-unknown", sample_invariants)
        assert result == "UNMATCHED"

    def test_single_invariant_fallback(self):
        from tee_audit.models.invariant import Invariant, InvariantFamily
        inv = Invariant(
            id="INV-99", description="x", trust_path="a→b",
            family=InvariantFamily.FLOW, sources=[], sinks=[],
            guards=[], failure_modes=[], codeql_expressible=False,
        )
        result = _match_invariant("anything", [inv])
        assert result == "INV-99"


class TestRunTriage:
    def test_full_triage(self, sample_sarif: Path, sample_invariants):
        inp = Stage5aInput(sarif_path=sample_sarif, invariants=sample_invariants)
        out = run_triage(inp)
        # 4 results: guard-check is a positive guard, others are graded findings
        assert len(out.graded_findings) >= 1
        assert len(out.positive_guards) >= 1

    def test_guard_separated(self, sample_sarif: Path, sample_invariants):
        inp = Stage5aInput(sarif_path=sample_sarif, invariants=sample_invariants)
        out = run_triage(inp)
        # The "custom-guard-check" rule should be a positive guard
        guard_ids = [pg.id for pg in out.positive_guards]
        assert len(guard_ids) >= 1

    def test_invariant_ids_assigned(self, sample_sarif: Path, sample_invariants):
        inp = Stage5aInput(sarif_path=sample_sarif, invariants=sample_invariants)
        out = run_triage(inp)
        inv_ids = {gf.invariant_id for gf in out.graded_findings}
        # At least some should match real invariant IDs
        assert inv_ids.intersection({"INV-01", "INV-02", "INV-03", "UNMATCHED"})
