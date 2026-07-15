"""Tests for the iteration-2 annotation resolver (verify -> repair -> reject)."""

from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
    merge_annotation_sets,
)
from tee_audit.trustir.resolver import resolve_set

_FIXTURE = """package main

func verifyQuote() bool { return true }

func registerAgent() {
\tderiveKey()
}

func deriveKey() {}
"""


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.go").write_text(_FIXTURE, encoding="utf-8")
    return repo


def _set() -> TrustAnnotationSet:
    return TrustAnnotationSet(
        repo="x",
        annotations=[
            TrustAnnotation(id="A", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="verifyQuote", file="src/x.go", line=2, claim_field_role="attested_public_key"),
            TrustAnnotation(id="B", kind=AnnotationKind.AUTHORITY, role="registration_acceptance",
                            name="registerAgent", file="src/x.go", line=4,
                            subject_param="agentAddr", subject_role="registered_agent"),
            TrustAnnotation(id="C", kind=AnnotationKind.SOURCE, role="host_input",
                            name="registerAgent", param="input", file="src/x.go", line=4),
            TrustAnnotation(id="D", kind=AnnotationKind.SINK, role="key_derivation_input",
                            name="deriveKey", file="src/x.go", line=5),
            TrustAnnotation(id="E", kind=AnnotationKind.GUARD, role="quote_signature_verification",
                            name="verifyQuote", file="src/x.go", line=2, dominates="registerAgent"),
            TrustAnnotation(id="F", kind=AnnotationKind.BINDING, role="subject_binding",
                            name="bind", from_ref="A", to_ref="B", accepted_relation="derived_equal"),
            TrustAnnotation(id="G", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="doesNotExist", file="src/x.go", line=2),
            TrustAnnotation(id="H", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="verifyQuote", file="src/x.go", line=99),
        ],
    )


def test_resolver_accept_repair_reject(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = resolve_set(_set(), repo, tolerance=3)
    by_id = {a.id: a for a in out["resolved"].annotations}

    assert by_id["A"].resolution_status == ResolutionStatus.ACCEPTED
    assert (by_id["A"].resolved_file, by_id["A"].resolved_line) == ("src/x.go", 3)

    assert by_id["B"].resolution_status == ResolutionStatus.ACCEPTED
    assert by_id["B"].resolved_line == 5

    assert by_id["C"].resolution_status == ResolutionStatus.ACCEPTED  # source fn def
    assert by_id["C"].resolved_line == 5

    assert by_id["D"].resolution_status == ResolutionStatus.ACCEPTED  # sink call site
    assert by_id["D"].resolved_line == 6
    assert by_id["D"].call_sites and any(
        s["line"] == 6 for s in by_id["D"].call_sites
    )

    assert by_id["E"].resolution_status == ResolutionStatus.ACCEPTED  # guard fn def
    assert by_id["E"].resolved_line == 3

    assert by_id["F"].resolution_status == ResolutionStatus.ACCEPTED  # binding both ends resolve
    assert by_id["F"].resolved_file == "src/x.go"

    assert by_id["G"].resolution_status == ResolutionStatus.REJECTED
    assert by_id["G"].resolution_note == "name_not_found"

    assert by_id["H"].resolution_status == ResolutionStatus.REPAIRED
    assert by_id["H"].resolved_line == 3
    assert "99->3" in by_id["H"].resolution_note

    assert out["stats"]["total"] == 8
    assert out["stats"]["accepted"] == 6
    assert out["stats"]["repaired"] == 1
    assert out["stats"]["rejected"] == 1
    assert len(out["rejected"]) == 1


def test_binding_rejected_when_endpoint_missing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    s = TrustAnnotationSet(
        repo="x",
        annotations=[
            TrustAnnotation(id="A", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="verifyQuote", file="src/x.go", line=2),
            TrustAnnotation(id="Z", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="ghost", file="src/x.go", line=2),
            TrustAnnotation(id="F", kind=AnnotationKind.BINDING, role="subject_binding",
                            name="bind", from_ref="A", to_ref="Z", accepted_relation="derived_equal"),
        ],
    )
    out = resolve_set(s, repo)
    by_id = {a.id: a for a in out["resolved"].annotations}
    assert by_id["F"].resolution_status == ResolutionStatus.REJECTED


def test_merge_dedups() -> None:
    a = TrustAnnotationSet(repo="x", annotations=[
        TrustAnnotation(id="1", kind=AnnotationKind.VERIFIER, role="r", name="f", file="a.go", line=1)])
    b = TrustAnnotationSet(repo="x", annotations=[
        TrustAnnotation(id="1", kind=AnnotationKind.VERIFIER, role="r", name="f", file="a.go", line=1),  # dup
        TrustAnnotation(id="2", kind=AnnotationKind.SINK, role="s", name="g", file="b.go", line=9)])
    merged = merge_annotation_sets([a, b])
    assert len(merged.annotations) == 2
