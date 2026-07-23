"""Tests for the iteration-2 result solver + path rendering (US-I2-06)."""

from __future__ import annotations

from tee_audit.trustir.reporter import render_md
from tee_audit.trustir.solver.result_solver import solve_from_results


def _qr(twe: str, violation: bool, *, path=None, error=None) -> dict:
    return {
        "twe_id": twe,
        "violation": violation,
        "count": 1 if violation else 0,
        "error": error,
        "results": [{"file": "a.go", "line": 5, "message": "unbound subject",
                     "path_steps": path or [
                         {"file": "a.go", "line": 2, "message": "attested key"},
                         {"file": "a.go", "line": 5, "message": "registered agent"}]}],
    }


def test_solve_fired_binding_is_confirmed_with_path() -> None:
    findings = solve_from_results([_qr("TWE-BIND-001", True)])
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "confirmed"  # Binding, not State/Design
    assert f["family"] == "Binding"
    assert len(f["path"]) == 2
    assert f["path"][0] == {"file": "a.go", "line": 2, "message": "attested key"}


def test_solve_state_violation_capped() -> None:
    findings = solve_from_results([_qr("TWE-STATE-001", True)])
    assert findings[0]["status"] != "confirmed"
    assert findings[0]["family"] == "State"


def test_solve_non_violation_produces_no_finding() -> None:
    findings = solve_from_results([_qr("TWE-FLOW-001", False)])
    assert findings == []


def test_solve_error_is_unresolved() -> None:
    findings = solve_from_results([{"twe_id": "TWE-LEAK-001", "violation": False, "error": "boom", "results": []}])
    assert findings[0]["status"] == "unresolved"
    assert "boom" in findings[0]["note"]


def test_markdown_renders_path() -> None:
    findings = solve_from_results([_qr("TWE-BIND-001", True)])
    md = render_md(findings, {"repo": "x"})
    assert "sink trace" in md
    assert "a.go:2" in md and "a.go:5" in md
    assert "attested key" in md
