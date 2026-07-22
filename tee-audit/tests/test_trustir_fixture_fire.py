"""US-011 fixture-fire: prove a TWE query FIRES on a known-good annotation + DB.

Hermetic — builds a tiny Go DB from tests/fixtures/trustir_flow001 (a host_input
parameter reaching a signing_input sink, no guard) and runs TWE-FLOW-001 with a
hand-crafted annotation set. Asserts the query fires (violation=True, count>=1)
and the finding carries a concrete source->sink path.

This validates the CodeQL query + fact-injection + solver path independently of
the suave-geth DB and the LLM. Skips when CodeQL is unavailable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.codeql_runner import build_or_get_db, run_all_queries

try:
    from tee_audit.utils.codeql_check import find_codeql
    _CODEQL = find_codeql()
except Exception:  # noqa: BLE001
    _CODEQL = None

FIXTURE = Path(__file__).parent / "fixtures" / "trustir_flow001"


def _mk(kind, role, name, **kw):
    return TrustAnnotation(
        id=f"a-{name}", kind=kind, role=role, name=name,
        resolution_status=ResolutionStatus.ACCEPTED, **kw,
    )


@pytest.mark.skipif(not _CODEQL, reason="CodeQL CLI not available")
def test_flow001_fires_on_fixture(tmp_path: Path):
    codeql = Path(_CODEQL)
    # 1. Build a source-only Go DB from the fixture.
    db, summary = build_or_get_db(FIXTURE, "go", codeql, tmp_path)
    assert db.exists(), f"DB not built: {summary}"

    # 2. Hand-crafted annotation set (name-only; the single-function fixture has
    #    no collisions, so name-only matching is exact here).
    resolved = TrustAnnotationSet(
        repo="trustir_flow001_fixture",
        language="go",
        annotations=[
            _mk(AnnotationKind.SOURCE, "host_input", "HandleRequest", param="userInput"),
            _mk(AnnotationKind.SINK, "signing_input", "Sign", sink_args=["0"]),
        ],
    )

    # 3. Run TWE-FLOW-001 against one injected facts module.
    work = tmp_path / "work"
    results = run_all_queries(db, "go", resolved, codeql, work, ["TWE-FLOW-001"])
    f001 = next((r for r in results if r["twe_id"] == "TWE-FLOW-001"), None)
    assert f001 is not None, "FLOW-001 result missing"
    assert f001.get("violation"), f"FLOW-001 should FIRE on the fixture: {f001}"
    assert f001.get("count", 0) >= 1

    # 4. The finding carries a concrete source->sink path (solver + path steps).
    from tee_audit.trustir.solver.result_solver import solve_from_results
    findings = solve_from_results([f001])
    assert findings, "solver produced no finding for the fired FLOW-001"
    fd = findings[0]
    assert fd["status"] in ("violated_candidate", "confirmed")  # honesty: Flow -> violated_candidate
    # at least one result carried path steps (the source->sink trace)
    has_path = any((r.get("path_steps")) for r in f001.get("results", []))
    assert has_path, "fired FLOW-001 produced no path steps"
