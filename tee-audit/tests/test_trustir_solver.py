"""Tests for the TrustIR obligation solver (US-006)."""

from __future__ import annotations

import pytest

from tee_audit.trustir.models import FindingStatus, TaxonomyFamily, TrustIR
from tee_audit.trustir.solver import classify, solve
from tee_audit.trustir.solver.obligation_solver import solve as solve_fn
from tee_audit.trustir.solver.status_classifier import classify_with_note
from tee_audit.trustir.solver.suppressor_checker import evaluate

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def raw_result(
    *,
    family: str = "Flow",
    violation: bool = False,
    out_of_scope: bool = False,
    twe_id: str = "TWE-X",
) -> dict:
    return {
        "family": family,
        "violation": violation,
        "out_of_scope": out_of_scope,
        "twe_id": twe_id,
    }


def empty_suppressors() -> dict:
    return {"test_only": False, "delegated": False, "guarded_elsewhere": False}


def empty_coverage() -> dict:
    return {"production_value_unknown": False, "missing_required_layer": False}


def minimal_ir(
    *,
    twe_id: str = "TWE-BIND-001",
    family: TaxonomyFamily = TaxonomyFamily.BINDING,
    suppressors: list[dict] | None = None,
) -> TrustIR:
    return TrustIR.model_validate(
        {
            "schema_version": "1.0",
            "repo": {"name": "demo", "root": "/repo"},
            "candidate_id": "C1",
            "twe_id": twe_id,
            "taxonomy_family": family.value,
            "trust_context": "onchain_attestation",
            "suppressors": suppressors if suppressors is not None else [],
            "required_obligations": [
                {
                    "id": "OBL1",
                    "twe_id": twe_id,
                    "family": family.value,
                    "authority_point_id": "AP1",
                }
            ],
        }
    )


# --------------------------------------------------------------------------- #
# classify()
# --------------------------------------------------------------------------- #


def test_classify_confirmed():
    status = classify(
        raw_result(violation=True), empty_suppressors(), empty_coverage()
    )
    assert status is FindingStatus.CONFIRMED
    assert status.value == "confirmed"


def test_classify_out_of_scope_wins():
    status = classify(
        raw_result(violation=True, out_of_scope=True),
        {"test_only": True, "delegated": True, "guarded_elsewhere": True},
        empty_coverage(),
    )
    assert status is FindingStatus.OUT_OF_SCOPE


@pytest.mark.parametrize("kind", ["test_only", "test_only_path", "mock", "example_only"])
def test_classify_test_only_suppressor(kind):
    flags = evaluate([{"kind": kind}])
    status = classify(raw_result(violation=True), flags, empty_coverage())
    assert status is FindingStatus.TEST_ONLY


def test_classify_delegated_suppressor():
    flags = evaluate([{"kind": "delegated"}, {"kind": "checked_inside_verifier"}])
    status = classify(raw_result(violation=True), flags, empty_coverage())
    assert status is FindingStatus.DELEGATED


def test_classify_guarded_elsewhere_suppressor():
    flags = evaluate([{"kind": "guarded_elsewhere"}, {"kind": "registry_enforces"}])
    status = classify(raw_result(violation=True), flags, empty_coverage())
    assert status is FindingStatus.GUARDED_ELSEWHERE


def test_classify_contract_enforces_is_guarded_elsewhere():
    flags = evaluate([{"kind": "contract_enforces"}])
    assert flags["guarded_elsewhere"] is True


def test_classify_config_configuration_dependent():
    status = classify(
        raw_result(family="Config", violation=True),
        empty_suppressors(),
        {"production_value_unknown": True, "missing_required_layer": False},
    )
    assert status is FindingStatus.CONFIGURATION_DEPENDENT


def test_classify_missing_required_layer_before_violation():
    status = classify(
        raw_result(violation=True),
        empty_suppressors(),
        {"production_value_unknown": False, "missing_required_layer": True},
    )
    assert status is FindingStatus.VIOLATED_CANDIDATE


def test_classify_out_of_scope_value():
    status = classify(
        raw_result(out_of_scope=True), empty_suppressors(), empty_coverage()
    )
    assert status.value == "out_of_scope"


def test_classify_unresolved_no_violation():
    status = classify(
        raw_result(violation=False), empty_suppressors(), empty_coverage()
    )
    assert status is FindingStatus.UNRESOLVED


# --------------------------------------------------------------------------- #
# State/Design cap
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "family",
    [TaxonomyFamily.STATE.value, TaxonomyFamily.DESIGN.value],
)
def test_state_design_capped(family):
    status = classify(
        raw_result(family=family, violation=True),
        empty_suppressors(),
        empty_coverage(),
    )
    assert status is FindingStatus.VIOLATED_CANDIDATE
    assert status.value == "violated_candidate"


def test_state_design_cap_never_confirmed():
    # Adversarial: even repeated checks must never produce CONFIRMED for State.
    status = classify(
        raw_result(family="State", violation=True), empty_suppressors(), empty_coverage()
    )
    assert status is not FindingStatus.CONFIRMED


def test_state_design_cap_sets_note():
    status, note = classify_with_note(
        raw_result(family="State", violation=True),
        empty_suppressors(),
        empty_coverage(),
    )
    assert status is FindingStatus.VIOLATED_CANDIDATE
    assert note == "manual_review_required:State"


def test_design_cap_sets_note():
    status, note = classify_with_note(
        raw_result(family="Design", violation=True),
        empty_suppressors(),
        empty_coverage(),
    )
    assert status is FindingStatus.VIOLATED_CANDIDATE
    assert note == "manual_review_required:Design"


def test_no_note_when_not_capped():
    status, note = classify_with_note(
        raw_result(family="Flow", violation=True),
        empty_suppressors(),
        empty_coverage(),
    )
    assert status is FindingStatus.CONFIRMED
    assert note == ""


# --------------------------------------------------------------------------- #
# suppressor_checker.evaluate()
# --------------------------------------------------------------------------- #


def test_evaluate_unknown_kind_ignored():
    flags = evaluate([{"kind": "something_new"}])
    assert flags == empty_suppressors()


def test_evaluate_missing_kind_ignored():
    flags = evaluate([{"not_kind": "test_only"}])
    assert flags == empty_suppressors()


def test_evaluate_combines_multiple():
    flags = evaluate(
        [
            {"kind": "test_only"},
            {"kind": "delegated"},
            {"kind": "registry_enforces"},
        ]
    )
    assert flags == {
        "test_only": True,
        "delegated": True,
        "guarded_elsewhere": True,
    }


# --------------------------------------------------------------------------- #
# solve()
# --------------------------------------------------------------------------- #


def test_solve_matching_result_confirmed():
    ir = minimal_ir(twe_id="TWE-BIND-001", family=TaxonomyFamily.BINDING)
    codeql_results = [
        {
            "twe_id": "TWE-BIND-001",
            "authority_point_id": "AP1",
            "violation": True,
        }
    ]
    findings = solve_fn(ir, codeql_results)
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "confirmed"
    assert f["twe_id"] == "TWE-BIND-001"
    assert f["candidate_id"] == "C1"
    assert f["family"] == "Binding"
    assert f["authority_point_id"] == "AP1"
    assert f["coverage_limits"] == []
    assert f["suppressors_checked"] == empty_suppressors()
    assert f["note"] == ""
    assert f["finding_id"] == "F1"


def test_solve_no_matching_result_unresolved():
    ir = minimal_ir(twe_id="TWE-BIND-001")
    codeql_results = [
        {"twe_id": "OTHER", "authority_point_id": "AP9", "violation": True}
    ]
    findings = solve_fn(ir, codeql_results)
    assert len(findings) == 1
    assert findings[0]["status"] == "unresolved"
    assert findings[0]["coverage_limits"] == ["no_codeql_result"]


def test_solve_passes_coverage_missing_required_layer():
    ir = minimal_ir()
    codeql_results = [
        {"twe_id": "TWE-BIND-001", "authority_point_id": "AP1", "violation": False}
    ]
    findings = solve_fn(ir, codeql_results, coverage={"missing_required_layer": True})
    assert findings[0]["status"] == "violated_candidate"


def test_solve_applies_ir_suppressors():
    ir = minimal_ir(suppressors=[{"kind": "test_only"}])
    codeql_results = [
        {"twe_id": "TWE-BIND-001", "authority_point_id": "AP1", "violation": True}
    ]
    findings = solve_fn(ir, codeql_results)
    assert findings[0]["status"] == "test_only"
    assert findings[0]["suppressors_checked"]["test_only"] is True


def test_solve_state_family_capped():
    ir = minimal_ir(twe_id="TWE-STATE-001", family=TaxonomyFamily.STATE)
    # rewrite the single obligation's twe_id to match
    ir.required_obligations[0] = ir.required_obligations[0].model_copy(
        update={"twe_id": "TWE-STATE-001", "family": TaxonomyFamily.STATE}
    )
    codeql_results = [
        {"twe_id": "TWE-STATE-001", "authority_point_id": "AP1", "violation": True}
    ]
    findings = solve_fn(ir, codeql_results)
    assert findings[0]["status"] == "violated_candidate"
    assert findings[0]["note"] == "manual_review_required:State"
    assert findings[0]["family"] == "State"


def test_solve_import_alias_matches():
    # solve is exported from the package; solve_fn is the direct import.
    assert solve is solve_fn
