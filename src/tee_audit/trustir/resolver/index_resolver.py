"""Iteration-3 resolver: verify->reject against the CodeQL EnumItemIndex.

Unlike v2's name-based verify/repair/reject (which repaired LLM file:line drift),
iteration-3 makes CodeQL the AUTHORITATIVE location source. The LLM no longer
proposes file:line — it labels a real enumerated node, and the resolver only
VERIFIES the reference exists in the index (plus role-catalog + sink_args range
checks), else REJECTS. There is no repair step: location cannot drift when CodeQL
owns it. Location/signature are INHERITED from the matched EnumItem.

Go key: ``(name, declaring_type)`` — kills name collisions (only
``pkg.ConfidentialEthBackend.Call`` matches, not geth's ``vmenv.Call``).
Rust key: ``(name, signature)`` (Decision-R; signature holds the arity/enclosing
disambiguator the fetch query emits).
"""

from __future__ import annotations

import functools
import yaml

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.enumeration import EnumItem, EnumItemIndex
from tee_audit.trustir.spec import bundled_spec_dir


@functools.lru_cache(maxsize=1)
def _catalog_roles() -> frozenset[str]:
    """All role/kind enum values across enum_registry.yml categories."""
    reg = yaml.safe_load((bundled_spec_dir() / "enum_registry.yml").read_text(encoding="utf-8"))
    roles: set[str] = set()
    for vals in (reg or {}).values():
        roles.update(vals)
    return frozenset(roles)


def _ground_rust(
    a: TrustAnnotation, idx: EnumItemIndex
) -> tuple[list[EnumItem], str] | None:
    """Resolve a Rust annotation against the index, returning ``(hits, mode)``.

    Exact ``(name, signature)`` first — this handles param-SOURCEs (signature is
    the enclosing function) and function/call annotations whose arity the LLM
    copied correctly.

    On an exact miss, function/call-anchored kinds fall back to NAME grounding:
    the LLM frequently emits the function NAME where the ARITY belongs
    (``signature="verify_qe_report_signature"`` instead of ``"2"``), so the
    exact key never matches and every real verify/collateral guard/source was
    dropped. We look up by name, prefer the ``function`` definition over call
    sites, collapse on a single arity, and INHERIT the authoritative arity +
    location from CodeQL (the LLM only supplied the semantic name + role).

    Param-SOURCEs stay strict — a bare param name is ambiguous across functions,
    so the enclosing-fn signature is required and never name-grounded. Returns
    ``None`` when the name is genuinely absent or ambiguous (multiple
    definitions with distinct arities and no disambiguating hint).
    """
    exact = idx.lookup(a.name, signature=a.signature)
    if exact:
        return exact, "exact"

    # A genuine param-SOURCE identifies a PARAMETER; its identity is
    # (param_name, enclosing_fn). The fact generator keys the SOURCE clause on
    # (a.param, a.signature), so the resolver grounds the same way (an LLM shape
    # variant puts the enclosing fn in BOTH name and signature, with the param
    # name only in a.param). Try the plausible (param, fn) pairs exactly. Never
    # name-ground a genuine param — a bare param name is ambiguous across
    # functions. When a.param just echoes the function name it is not a real
    # param; fall through to function-anchored name grounding below.
    if (
        a.kind is AnnotationKind.SOURCE
        and a.param
        and a.param != a.name
        and a.param != a.signature
    ):
        for pn, fn in ((a.param, a.signature), (a.name, a.signature), (a.param, a.name)):
            if pn and fn and pn != fn:
                hit = idx.lookup(pn, signature=fn)
                if hit:
                    return hit, "exact"
        return None

    by_name = idx.lookup_by_name(a.name)
    if not by_name:
        return None

    # Prefer a function definition (canonical, one-per-module) over call sites.
    defs = [h for h in by_name if h.kind == "function"]
    cands = defs or by_name

    # Honor a numeric arity hint if the LLM happened to supply a real arity.
    sig = (a.signature or "").strip()
    if sig.lstrip("-").isdigit():
        hinted = [h for h in cands if str(h.signature or "") == sig]
        if hinted:
            cands = hinted

    arities = {str(h.signature or "") for h in cands}
    if len(cands) == 1:
        return cands, "name_grounding_unique"
    if len(arities) == 1:
        return cands, "name_grounding_single_arity"
    return None  # genuinely ambiguous: multiple defs, distinct arities, no hint


def resolve_against_index(
    ann_set: TrustAnnotationSet,
    enum_index: EnumItemIndex,
    language: str,
) -> TrustAnnotationSet:
    """Verify->reject each annotation against the EnumItemIndex (in-place + return).

    Accept: ref found in index (location/signature inherited from the EnumItem),
    role is a catalog value (for non-binding kinds), and sink_args in range.
    Reject otherwise. Rejected annotations never reach the facts module
    (the generator's ``_accepted`` filter drops them).
    """
    catalog = _catalog_roles()
    for a in ann_set.annotations:
        # 1. role-catalog gate (binding relations are resolved separately).
        if a.kind != AnnotationKind.BINDING and a.role and a.role not in catalog:
            a.resolution_status = ResolutionStatus.REJECTED
            a.resolution_note = f"role_not_in_catalog:{a.role}"
            continue

        # 2. index lookup by the language-appropriate key.
        mode = "exact"
        if language == "rust":
            grounded = _ground_rust(a, enum_index)
            if grounded is None:
                a.resolution_status = ResolutionStatus.REJECTED
                a.resolution_note = f"ref_not_found:{a.name}@{a.declaring_type or a.signature}"
                continue
            hits, mode = grounded
        else:
            hits = enum_index.lookup(a.name, declaring_type=a.declaring_type)
            if not hits:
                a.resolution_status = ResolutionStatus.REJECTED
                a.resolution_note = f"ref_not_found:{a.name}@{a.declaring_type or a.signature}"
                continue

        # 3. sink_args range check (SINK only, when the call's arg_count is known).
        if a.kind == AnnotationKind.SINK and a.sink_args:
            arg_count = hits[0].arg_count
            bad = [
                i for i in a.sink_args
                if str(i).lstrip("-").isdigit() and arg_count is not None and int(i) >= arg_count
            ]
            if bad:
                a.resolution_status = ResolutionStatus.REJECTED
                a.resolution_note = f"sink_args_out_of_range:{bad} vs arg_count={arg_count}"
                continue

        # 4. accept: inherit authoritative location + signature from CodeQL.
        hit = hits[0]
        a.resolution_status = ResolutionStatus.ACCEPTED
        a.resolved_file = hit.file
        a.resolved_line = hit.line
        # Name-grounded Rust annotations: the LLM's signature was wrong (it
        # emitted the function name, not the arity) — inherit the real arity.
        # Exact matches already agree; empty signatures inherit as before.
        if mode != "exact" and hit.signature:
            a.signature = hit.signature
        elif not a.signature and hit.signature:
            a.signature = hit.signature
        # backfill declaring_type components if the LLM omitted them (Go).
        if language != "rust":
            if not a.declaring_type_pkg:
                a.declaring_type_pkg = hit.declaring_type_pkg
            if not a.declaring_type_type:
                a.declaring_type_type = hit.declaring_type_type
        a.resolution_note = "index_resolved" if mode == "exact" else f"index_resolved({mode})"
    return ann_set


__all__ = ["resolve_against_index", "_catalog_roles"]
