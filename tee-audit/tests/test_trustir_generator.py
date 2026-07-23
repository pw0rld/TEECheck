"""Tests for the CodeQL fact generator + query-plan generator (US-003)."""

from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.binder.resolver import BindResult, Resolution
from tee_audit.trustir.generator import build_query_plan, generate_facts, generate_facts_file
from tee_audit.trustir.generator.codeql_fact_generator import normalize_language
from tee_audit.trustir.generator.query_plan_generator import all_twe_ids, query_module_for
from tee_audit.trustir.models import TrustIR


def _ir() -> TrustIR:
    return TrustIR.model_validate(
        {
            "schema_version": "1.0",
            "repo": {"name": "x", "root": "/repo"},
            "candidate_id": "C1",
            "twe_id": "TWE-BIND-001",
            "taxonomy_family": "Binding",
            "trust_context": "agent_registration",
            "claim_fields": [
                {"id": "CF1", "selector": "receipt.publicKey", "role": "attested_public_key"},
                {"id": "CF2", "selector": "out.tcb_status", "role": "tcb_status"},
            ],
            "authority_points": [
                {
                    "id": "AP1",
                    "kind": "registration_acceptance",
                    "selector": {"language": "go", "file": "src/register.go",
                                 "qualified_name": "registerAgent", "line": 29},
                    "authority_subject": {"selector": "req.agentAddress", "role": "registered_agent"},
                }
            ],
            "required_obligations": [
                {"id": "O1", "twe_id": "TWE-BIND-001", "family": "Binding",
                 "authority_point_id": "AP1"}
            ],
        }
    )


def _result() -> BindResult:
    ir = _ir()
    resolutions = {
        "CF1": Resolution(fact_id="CF1", status="resolved",
                          node={"file": "src/register.go", "line": 21, "token": "publicKey"}),
        # CF2 deliberately REJECTED — must not appear in facts (zero-hallucination).
        "CF2": Resolution(fact_id="CF2", status="rejected", reason="field_not_found"),
        "AP1": Resolution(fact_id="AP1", status="resolved",
                          node={"file": "src/register.go", "line": 29, "qualified_name": "registerAgent"}),
        "AP1.authority_subject": Resolution(
            fact_id="AP1.authority_subject", status="resolved",
            node={"file": "src/register.go", "line": 29, "token": "agentAddress"}),
    }
    return BindResult(resolved=ir, resolutions=resolutions)


def test_generate_facts_go_structure_and_facts_only() -> None:
    out = generate_facts(_result(), "go")
    assert "import go" in out
    assert "module GeneratedTrustFacts" in out
    # resolved claim field emitted with role + file + line
    assert "attested_public_key" in out
    assert "src/register.go" in out
    assert "getStartLine() = 21" in out
    assert "getStartLine() = 29" in out  # authority point line
    # rejected fact must NOT be emitted
    assert "tcb_status" not in out
    # facts only: no vulnerability query constructs
    assert "select " not in out
    assert "TaintTracking" not in out
    assert "Global<" not in out


def test_generate_facts_language_javascript() -> None:
    out = generate_facts(_result(), "typescript")
    assert "import javascript" in out
    assert "attested_public_key" in out


def test_generate_facts_authority_subject_and_kind() -> None:
    out = generate_facts(_result(), "go")
    assert "registration_acceptance" in out  # authority kind
    assert "registered_agent" in out  # authority subject role


def test_normalize_language_rejects_unknown() -> None:
    try:
        normalize_language("python")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_generate_facts_file_writes(tmp_path: Path) -> None:
    out_path = tmp_path / "work" / "common" / "GeneratedTrustFacts.qll"
    p = generate_facts_file(_result(), "go", out_path)
    assert p.exists()
    assert "module GeneratedTrustFacts" in p.read_text()


def test_build_query_plan_bind_001() -> None:
    plan = build_query_plan("C1", "TWE-BIND-001", "go", "/packs/go")
    assert plan["twe_id"] == "TWE-BIND-001"
    assert plan["generated_facts"] == "common/GeneratedTrustFacts.qll"
    assert plan["queries"] == ["/packs/go/binding/MissingSubjectBinding.ql"]


def test_query_module_for_all_16_twe() -> None:
    ids = all_twe_ids()
    assert len(ids) == 16
    for tid in ids:
        assert query_module_for(tid).endswith(".ql")
