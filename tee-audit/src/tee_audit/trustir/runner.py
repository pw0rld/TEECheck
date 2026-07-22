"""Deterministic TrustIR orchestration runner (bind → solve).

The full pipeline (extract → bind → generate facts → run CodeQL → solve → report)
is assembled by the CLI. This module provides the deterministic, side-effect-free
core that is independently testable: given a candidate IR and (optional) CodeQL
results, it binds the IR to the repo and solves obligations into findings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tee_audit.trustir.binder import bind
from tee_audit.trustir.models import TrustIR
from tee_audit.trustir.solver import solve


def resolve_and_solve(
    candidate_ir: TrustIR,
    repo_root: str | Path,
    codeql_results: list[dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind ``candidate_ir`` to ``repo_root`` and solve obligations.

    Returns a dict with ``findings``, ``bind_summary``, ``rejected`` facts, and a
    compact per-fact ``resolutions`` map. ``codeql_results`` is the list of CodeQL
    query outcomes (``{twe_id, authority_point_id?, violation, out_of_scope?}``).
    """
    result = bind(candidate_ir, Path(repo_root))
    findings = solve(result.resolved, codeql_results or [], coverage or {})

    return {
        "findings": findings,
        "bind_summary": result.resolved.resolution_summary,
        "rejected": result.rejected,
        "resolutions": {
            fact_id: {"status": res.status, "reason": res.reason}
            for fact_id, res in result.resolutions.items()
        },
    }


__all__ = ["resolve_and_solve"]
