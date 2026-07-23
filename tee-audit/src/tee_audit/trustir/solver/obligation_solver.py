"""Top-level obligation solver: TrustIR + CodeQL results -> finding dicts.

For each ``required_obligation`` declared in the IR, the solver looks up the
matching CodeQL obligation-check result (by ``twe_id``), assembles the raw
result / suppressor / coverage inputs, classifies the finding conservatively
(design 10.3, with the State/Design cap), and emits a finding dict.
"""

from __future__ import annotations

from typing import Any

from tee_audit.trustir.models import TrustIR
from tee_audit.trustir.solver.status_classifier import classify_with_note
from tee_audit.trustir.solver.suppressor_checker import evaluate as evaluate_suppressors


def solve(
    ir: TrustIR,
    codeql_results: list[dict],
    coverage: dict | None = None,
) -> list[dict]:
    """Produce one finding dict per required obligation in ``ir``.

    Parameters
    ----------
    ir:
        Resolved TrustIR carrying ``required_obligations`` and ``suppressors``.
    codeql_results:
        One dict per CodeQL obligation-check result. Each has at least
        ``twe_id``, ``authority_point_id``, ``violation``; optional ``out_of_scope``.
    coverage:
        Coverage report dict; defaults to ``{}``. Recognized keys:
        ``production_value_unknown``, ``missing_required_layer``.
    """
    if coverage is None:
        coverage = {}

    suppressors = evaluate_suppressors(list(ir.suppressors))

    # Index CodeQL results by twe_id for deterministic lookup.
    results_by_twe: dict[str, dict] = {}
    for result in codeql_results:
        twe_id = result.get("twe_id")
        if isinstance(twe_id, str) and twe_id not in results_by_twe:
            results_by_twe[twe_id] = result

    findings: list[dict[str, Any]] = []
    for index, obligation in enumerate(ir.required_obligations, start=1):
        family_value = obligation.family.value
        matched = results_by_twe.get(obligation.twe_id)

        if matched is None:
            findings.append(
                _build_finding(
                    index=index,
                    ir=ir,
                    obligation=obligation,
                    authority_point_id=obligation.authority_point_id,
                    status_value="unresolved",
                    note="",
                    coverage_limits=["no_codeql_result"],
                    suppressors_checked=suppressors,
                )
            )
            continue

        raw_result = {
            "twe_id": obligation.twe_id,
            "family": family_value,
            "violation": bool(matched.get("violation", False)),
            "out_of_scope": bool(matched.get("out_of_scope", False)),
        }

        status, note = classify_with_note(raw_result, suppressors, coverage)

        findings.append(
            _build_finding(
                index=index,
                ir=ir,
                obligation=obligation,
                authority_point_id=matched.get(
                    "authority_point_id", obligation.authority_point_id
                ),
                status_value=status.value,
                note=note,
                coverage_limits=[],
                suppressors_checked=suppressors,
            )
        )

    return findings


def _build_finding(
    *,
    index: int,
    ir: TrustIR,
    obligation,
    authority_point_id: str,
    status_value: str,
    note: str,
    coverage_limits: list[str],
    suppressors_checked: dict,
) -> dict[str, Any]:
    return {
        "finding_id": f"F{index}",
        "candidate_id": ir.candidate_id,
        "twe_id": obligation.twe_id,
        "family": obligation.family.value,
        "authority_point_id": authority_point_id,
        "status": status_value,
        "summary": _summary(obligation, status_value),
        "suppressors_checked": dict(suppressors_checked),
        "coverage_limits": list(coverage_limits),
        "note": note,
    }


def _summary(obligation, status_value: str) -> str:
    return (
        f"Obligation {obligation.twe_id} ({obligation.family.value}) "
        f"at {obligation.authority_point_id}: {status_value}."
    )


__all__ = ["solve"]
