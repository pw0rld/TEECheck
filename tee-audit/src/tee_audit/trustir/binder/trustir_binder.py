"""High-level binder entry points: ``bind`` and ``bind_file``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tee_audit.trustir.binder.resolver import (
    BindResult,
    Resolution,
    assert_no_hallucinated_resolutions,
    resolve_evidence_span,
    resolve_field_selector,
    resolve_file,
    resolve_selector,
)
from tee_audit.trustir.loader import load_trustir
from tee_audit.trustir.models import TrustIR


def _record(
    result: BindResult,
    fact_id: str,
    kind: str,
    resolution: Resolution,
    counts: dict[str, int],
) -> None:
    """Record a resolution: store it, tally, and push to rejected if rejected."""
    result.resolutions[fact_id] = resolution
    counts["total"] += 1
    if resolution.status in counts:
        counts[resolution.status] += 1
    if resolution.status == "rejected":
        result.rejected.append(
            {
                "fact_id": fact_id,
                "kind": kind,
                "status": resolution.status,
                "reason": resolution.reason,
            }
        )


def bind(ir: TrustIR, repo_root: Path, tolerance: int = 2) -> BindResult:
    """Resolve every fact in ``ir`` against ``repo_root`` and return a BindResult.

    Per-fact resolutions are stored in ``result.resolutions`` (keyed by fact id).
    The input IR is returned with a top-level ``resolution_summary`` attached.
    """
    repo_root = Path(repo_root).resolve()
    result = BindResult(resolved=ir)
    counts = {"total": 0, "resolved": 0, "rejected": 0, "unresolved": 0}

    # --- Claim producers (Selector form) ---
    for producer in ir.claim_producers:
        res = resolve_selector(producer.selector, repo_root, producer.id, tolerance)
        _record(result, producer.id, "claim_producer", res, counts)

    # --- Claim fields (field-access string + producer_id) ---
    producer_file_by_id: dict[str, str] = {
        p.id: p.selector.file for p in ir.claim_producers if p.selector.file
    }
    evidence_file_by_id: dict[str, str] = {e.id: e.file for e in ir.evidence_spans}
    for cf in ir.claim_fields:
        producer_file: str | None = None
        if cf.producer_id and cf.producer_id in producer_file_by_id:
            producer_file = producer_file_by_id[cf.producer_id]

        fallback_file: str | None = None
        if cf.evidence_span_ids:
            fallback_file = evidence_file_by_id.get(cf.evidence_span_ids[0])

        res = resolve_field_selector(
            cf.selector, producer_file, repo_root, cf.id, fallback_file=fallback_file
        )
        _record(result, cf.id, "claim_field", res, counts)

    # --- Authority points (Selector form) + authority_subject (string) ---
    for ap in ir.authority_points:
        res = resolve_selector(ap.selector, repo_root, ap.id, tolerance)
        _record(result, ap.id, "authority_point", res, counts)

        # Authority subject field-access selector against the authority's file.
        if ap.authority_subject is not None and ap.authority_subject.selector:
            sub_id = f"{ap.id}.authority_subject"
            sub_res = resolve_field_selector(
                ap.authority_subject.selector,
                ap.selector.file,
                repo_root,
                sub_id,
                fallback_file=None,
            )
            _record(result, sub_id, "authority_subject", sub_res, counts)

    # --- Guards (optional Selector form) ---
    for g in ir.guards:
        if g.selector is not None:
            res = resolve_selector(g.selector, repo_root, g.id, tolerance)
            _record(result, g.id, "guard", res, counts)
        else:
            # Guards without a selector are out of scope for the binder.
            res = Resolution(fact_id=g.id, status="unresolved", reason="no_selector")
            _record(result, g.id, "guard", res, counts)

    # --- Binding relations: no file to check, skipped. ---

    # --- Evidence spans ---
    for span in ir.evidence_spans:
        res = resolve_evidence_span(span, repo_root)
        _record(result, span.id, "evidence_span", res, counts)

    # Sanity: confirm repo_root itself exists (no-op-style check).
    _root, _ = resolve_file(".", repo_root)

    ir.resolution_summary = {
        "total": counts["total"],
        "resolved": counts["resolved"],
        "rejected": counts["rejected"],
        "unresolved": counts["unresolved"],
        "repo_root": str(repo_root),
    }
    result.coverage = counts

    # Zero-hallucination invariant.
    assert_no_hallucinated_resolutions(result, repo_root)
    return result


def bind_file(
    candidate_json_path: str | Path, repo_root: str | Path, tolerance: int = 2
) -> BindResult:
    """Load a TrustIR candidate JSON file from disk and bind it."""
    ir = load_trustir(candidate_json_path)
    return bind(ir, Path(repo_root), tolerance=tolerance)
