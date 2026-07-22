"""Tests for the TrustIR orchestration runner (US-008 part A)."""

from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.models import TaxonomyFamily, TrustIR
from tee_audit.trustir.runner import resolve_and_solve


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "register.go").write_text(
        "package main\n"
        "\n"
        "func verifyReceipt() bool { return true }\n"
        "\n"
        "func registerAgent() {\n"
        "\t_ = verifyReceipt()\n"
        "\tregisterAgent()\n"
        "}\n",
        encoding="utf-8",
    )
    return repo


def _ir(repo: Path) -> TrustIR:
    return TrustIR.model_validate(
        {
            "schema_version": "1.0",
            "repo": {"name": "x", "root": str(repo)},
            "candidate_id": "C1",
            "twe_id": "TWE-BIND-001",
            "taxonomy_family": "Binding",
            "trust_context": "agent_registration",
            "claim_fields": [
                {"id": "CF1", "selector": "receipt.publicKey", "role": "attested_public_key"},
            ],
            "authority_points": [
                {
                    "id": "AP1",
                    "kind": "registration_acceptance",
                    "selector": {"language": "go", "file": "src/register.go",
                                 "qualified_name": "registerAgent", "line": 7},
                    "authority_subject": {"selector": "req.agentAddress", "role": "registered_agent"},
                }
            ],
            "required_obligations": [
                {"id": "O1", "twe_id": "TWE-BIND-001", "family": "Binding",
                 "authority_point_id": "AP1"}
            ],
        }
    )


def test_resolve_and_solve_with_violation(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    out = resolve_and_solve(
        _ir(repo), repo,
        codeql_results=[{"twe_id": "TWE-BIND-001", "authority_point_id": "AP1", "violation": True}],
    )
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    # Binding family + violation + full coverage -> confirmed (not State/Design, no cap).
    assert f["status"] in {"confirmed", "violated_candidate"}
    assert f["twe_id"] == "TWE-BIND-001"
    assert out["bind_summary"]["total"] >= 1


def test_resolve_and_solve_no_codeql_result_is_unresolved(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    out = resolve_and_solve(_ir(repo), repo, codeql_results=[])
    assert out["findings"][0]["status"] == "unresolved"
    assert "no_codeql_result" in out["findings"][0]["coverage_limits"]


def test_resolve_and_solve_state_family_capped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    ir = _ir(repo)
    # Re-cast as a State TWE to exercise the solver cap.
    ir.twe_id = "TWE-STATE-001"
    ir.taxonomy_family = TaxonomyFamily.STATE
    ir.required_obligations[0].twe_id = "TWE-STATE-001"
    ir.required_obligations[0].family = ir.taxonomy_family
    out = resolve_and_solve(
        ir, repo,
        codeql_results=[{"twe_id": "TWE-STATE-001", "authority_point_id": "AP1", "violation": True}],
    )
    # State violations are capped: never confirmed.
    assert out["findings"][0]["status"] != "confirmed"
