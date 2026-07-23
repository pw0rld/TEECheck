"""The deterministic annotation resolver (iteration 2): verify -> repair -> reject.

Each LLM annotation carries a name (the repair key) and a claimed file:line (the
grounding claim). The resolver checks the name against a real symbol index:

* verifier / authority / guard / source : name is a function DEFINITION ->
  lookup the def; accept if at/near the claimed line, else repair to the real
  def location; reject if the name does not exist.
* sink : name is a CALLEE -> enumerate call sites; accept/repair/reject likewise.
* binding : file:line optional; resolved iff its from_ref/to_ref anchors resolve.

Rejected annotations never reach the CodeQL facts module (hallucination guard).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.resolver.symbol_index import bare_name, find_call_sites, index_function_defs

# Kinds anchored to a function definition (resolved via def lookup).
_FUNCTION_KINDS = {AnnotationKind.VERIFIER, AnnotationKind.AUTHORITY,
                   AnnotationKind.GUARD, AnnotationKind.SOURCE}


class SymbolIndex:
    """Function-definition index over a repo, plus on-demand call-site lookup."""

    def __init__(self, defs: dict[str, list[tuple[str, int]]], repo_root: Path):
        self.defs = defs
        self.repo_root = Path(repo_root)

    @classmethod
    def build(cls, repo_root: Path) -> "SymbolIndex":
        return cls(index_function_defs(Path(repo_root)), Path(repo_root))

    def call_sites(self, name: str) -> list[tuple[str, int]]:
        return find_call_sites(self.repo_root, name)

    def lookup_def(self, name: str) -> list[tuple[str, int]]:
        """Definition candidates for ``name``, trying the bare form if qualified."""
        if name in self.defs:
            return self.defs[name]
        tail = bare_name(name)
        return self.defs.get(tail, []) if tail != name else []

    def lookup_call_sites(self, name: str) -> list[tuple[str, int]]:
        """Call-site candidates for ``name``, trying the bare form if qualified."""
        sites = self.call_sites(name)
        if sites or "." not in name:
            return sites
        return self.call_sites(bare_name(name))


def _filter_by_hint(
    candidates: list[tuple[str, int]], ann: TrustAnnotation
) -> list[tuple[str, int]]:
    hint = ann.path_hint or ann.file
    if not hint:
        return candidates
    preferred = [c for c in candidates if hint in c[0] or c[0] in hint]
    return preferred or candidates


def _nearest(line: int, candidates: list[tuple[str, int]]) -> tuple[str, int]:
    return min(candidates, key=lambda c: abs(c[1] - line))


def _resolve_function_like(
    ann: TrustAnnotation, index: SymbolIndex, tolerance: int
) -> None:
    candidates = index.lookup_def(ann.name)
    candidates = _filter_by_hint(candidates, ann)
    if not candidates:
        ann.resolution_status = ResolutionStatus.REJECTED
        ann.resolution_note = "name_not_found"
        return
    if ann.line is None:
        ann.resolution_status = ResolutionStatus.ACCEPTED
        ann.resolved_file, ann.resolved_line = candidates[0]
        ann.resolution_note = "no_line_claim"
        return
    best = _nearest(ann.line, candidates)
    ann.resolved_file, ann.resolved_line = best
    if abs(best[1] - ann.line) <= tolerance:
        ann.resolution_status = ResolutionStatus.ACCEPTED
        if best[1] != ann.line:
            ann.resolution_note = f"line_confirmed_within_tolerance:{ann.line}->{best[1]}"
    else:
        ann.resolution_status = ResolutionStatus.REPAIRED
        ann.resolution_note = f"line_repaired:{ann.line}->{best[1]}"


def _resolve_sink(ann: TrustAnnotation, index: SymbolIndex, tolerance: int) -> None:
    sites = index.lookup_call_sites(ann.name)
    sites = _filter_by_hint(sites, ann)
    ann.call_sites = [{"file": f, "line": ln} for f, ln in sites]
    if not sites:
        ann.resolution_status = ResolutionStatus.REJECTED
        ann.resolution_note = "call_site_not_found"
        return
    if ann.line is None:
        ann.resolution_status = ResolutionStatus.ACCEPTED
        ann.resolved_file, ann.resolved_line = sites[0]
        return
    best = _nearest(ann.line, sites)
    ann.resolved_file, ann.resolved_line = best
    if abs(best[1] - ann.line) <= tolerance:
        ann.resolution_status = ResolutionStatus.ACCEPTED
    else:
        ann.resolution_status = ResolutionStatus.REPAIRED
        ann.resolution_note = f"call_site_repaired:{ann.line}->{best[1]}"


def _resolve_binding(
    ann: TrustAnnotation, resolved_by_id: dict[str, TrustAnnotation]
) -> None:
    fr = resolved_by_id.get(ann.from_ref) if ann.from_ref else None
    to = resolved_by_id.get(ann.to_ref) if ann.to_ref else None
    ok_from = fr is not None and fr.resolution_status != ResolutionStatus.REJECTED
    ok_to = to is not None and to.resolution_status != ResolutionStatus.REJECTED
    if ok_from and ok_to:
        ann.resolution_status = ResolutionStatus.ACCEPTED
        ann.resolved_file = fr.resolved_file
        ann.resolved_line = fr.resolved_line
    else:
        ann.resolution_status = ResolutionStatus.REJECTED
        ann.resolution_note = "binding_endpoint_unresolved"


def resolve_annotation(
    ann: TrustAnnotation, index: SymbolIndex, tolerance: int = 3
) -> TrustAnnotation:
    """Resolve a single annotation in place and return it."""
    if ann.kind in _FUNCTION_KINDS:
        _resolve_function_like(ann, index, tolerance)
    elif ann.kind == AnnotationKind.SINK:
        _resolve_sink(ann, index, tolerance)
    elif ann.kind == AnnotationKind.BINDING:
        # resolved later in resolve_set (needs other annotations)
        return ann
    else:  # pragma: no cover - defensive
        ann.resolution_status = ResolutionStatus.REJECTED
        ann.resolution_note = "unknown_kind"
    return ann


def resolve_set(
    annotation_set: TrustAnnotationSet,
    repo_root: str | Path,
    tolerance: int = 3,
) -> dict[str, Any]:
    """Resolve every annotation in the set against ``repo_root``.

    Returns ``{"resolved": TrustAnnotationSet, "rejected": list[dict], "stats": dict}``.
    Bindings are resolved after the node-anchored kinds (they reference them).
    """
    index = SymbolIndex.build(Path(repo_root))

    # Pass 1: node-anchored kinds.
    for ann in annotation_set.annotations:
        if ann.kind != AnnotationKind.BINDING:
            resolve_annotation(ann, index, tolerance)

    resolved_by_id: dict[str, TrustAnnotation] = {
        a.id: a for a in annotation_set.annotations
    }
    # Pass 2: bindings.
    for ann in annotation_set.annotations:
        if ann.kind == AnnotationKind.BINDING:
            _resolve_binding(ann, resolved_by_id)

    rejected = [
        {"id": a.id, "kind": a.kind.value, "role": a.role, "name": a.name,
         "reason": a.resolution_note}
        for a in annotation_set.annotations
        if a.resolution_status == ResolutionStatus.REJECTED
    ]
    stats = {
        "total": len(annotation_set.annotations),
        "accepted": sum(1 for a in annotation_set.annotations if a.resolution_status == ResolutionStatus.ACCEPTED),
        "repaired": sum(1 for a in annotation_set.annotations if a.resolution_status == ResolutionStatus.REPAIRED),
        "rejected": len(rejected),
    }
    return {"resolved": annotation_set, "rejected": rejected, "stats": stats}


__all__ = ["SymbolIndex", "resolve_annotation", "resolve_set"]
