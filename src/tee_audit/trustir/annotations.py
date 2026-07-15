"""TrustIR annotations (iteration 2): the LLM -> resolver -> CodeQL bridge.

The LLM emits role-tagged, name-based annotations with a required ``file:line``
(grounding discipline + primary evidence). The deterministic resolver then
verify/repair/reject each anchor by NAME (file:line is the LLM's claim; name is
the repair key). Resolved annotations are consumed by the fact generator.

Unlike v1's exact-line ``claim_fields``, annotations are role-tagged at
function/parameter/call granularity so CodeQL can resolve them to real
data-flow nodes and trace actual source->sink paths.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class AnnotationKind(str, Enum):
    """What an annotation anchors to in the code."""

    VERIFIER = "verifier"      # claim-producer function (e.g. verifyQuote)
    AUTHORITY = "authority"    # authority-point function (e.g. registerAgent)
    SOURCE = "source"          # trust source: a function parameter (host input)
    SINK = "sink"              # trust sink: a call (e.g. deriveKey(...))
    GUARD = "guard"            # guard function that must dominate an authority
    BINDING = "binding"        # relation linking a claim to a subject/context
    PROPAGATOR = "propagator"  # taint input->output carrier (isAdditionalTrustFlowStep)


class ResolutionStatus(str, Enum):
    ACCEPTED = "accepted"   # name found at/near claimed file:line
    REPAIRED = "repaired"   # name found, but line corrected
    REJECTED = "rejected"   # name absent (hallucination) / unresolvable


class TrustAnnotation(BaseModel):
    """One LLM-proposed semantic anchor + its deterministic resolution.

    ``name`` + ``file`` + ``line`` are the LLM's claim (file:line required for
    node-anchored kinds; optional for binding). The resolver fills the
    ``resolved_*`` / ``resolution_status`` fields.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    kind: AnnotationKind
    role: str                       # semantic role (enum-registry value)
    name: str                       # function/param/call name (repair key)
    file: str | None = None         # LLM-claimed path (grounding)
    line: int | None = None         # LLM-claimed line (grounding)
    path_hint: str | None = None    # optional disambiguation path
    receiver_type: str | None = None

    # iteration-3 structural identity (authoritative source = CodeQL enumeration,
    # NOT the LLM). declaring_type_pkg/declaring_type_type are the Go callee's
    # import path + receiver type (separate, because Go's 3-arg
    # hasQualifiedName(pkg,type,name) needs them apart); for Rust both are None
    # (rust-all 0.2.4 exposes no qualification API — Decision-R). signature is the
    # function/call signature (Rust precision key). sink_args pins the vulnerable
    # argument(s) of a SINK by position / "this" / param name (IRIS sink_args).
    declaring_type_pkg: str | None = None
    declaring_type_type: str | None = None
    signature: str | None = None
    sink_args: list[str] | None = None

    @property
    def declaring_type(self) -> str | None:
        """Combined ``pkg.Type`` (Go) for index lookup; None when neither set."""
        if self.declaring_type_pkg and self.declaring_type_type:
            return f"{self.declaring_type_pkg}.{self.declaring_type_type}"
        return self.declaring_type_type or self.declaring_type_pkg

    # kind-specific extras (all optional)
    param: str | None = None                # SOURCE: the parameter name
    claim_field_role: str | None = None     # VERIFIER: produced claim-field role
    accessor: str | None = None             # VERIFIER: e.g. "report.PublicKey"
    subject_param: str | None = None        # AUTHORITY: param carrying the subject
    subject_role: str | None = None         # AUTHORITY: subject role
    protected_asset: str | None = None      # AUTHORITY: protected asset
    dominates: str | None = None            # GUARD: authority name it dominates
    from_ref: str | None = None             # BINDING: source annotation id / accessor
    to_ref: str | None = None               # BINDING: target annotation id / accessor
    accepted_relation: str | None = None    # BINDING: relation kind

    # resolver output
    resolution_status: ResolutionStatus | None = None
    resolved_file: str | None = None
    resolved_line: int | None = None
    resolution_note: str | None = None
    call_sites: list[dict[str, Any]] | None = None  # SINK: resolved call sites


class TrustAnnotationSet(BaseModel):
    """All annotations for one repo (merged across zones), pre- or post-resolution."""

    repo: str
    commit: str | None = None
    language: str | None = None
    annotations: list[TrustAnnotation] = []

    def by_kind(self, kind: AnnotationKind) -> list[TrustAnnotation]:
        return [a for a in self.annotations if a.kind == kind]

    def by_id(self, aid: str) -> TrustAnnotation | None:
        for a in self.annotations:
            if a.id == aid:
                return a
        return None


def merge_annotation_sets(sets: list[TrustAnnotationSet]) -> TrustAnnotationSet:
    """Merge per-zone annotation sets into one, deduping by (kind, role, name, file, line)."""
    seen: set[tuple] = set()
    merged: list[TrustAnnotation] = []
    repo = sets[0].repo if sets else ""
    for s in sets:
        repo = repo or s.repo
        for a in s.annotations:
            key = (a.kind.value, a.role, a.name, a.file, a.line)
            if key in seen:
                continue
            seen.add(key)
            merged.append(a)
    return TrustAnnotationSet(
        repo=repo,
        language=sets[0].language if sets else None,
        annotations=merged,
    )


__all__ = [
    "AnnotationKind",
    "ResolutionStatus",
    "TrustAnnotation",
    "TrustAnnotationSet",
    "merge_annotation_sets",
]
