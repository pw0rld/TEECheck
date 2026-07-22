"""Sink-precision guard (US-I2-05): the name-based fact generator must NOT emit a
sink whose role belongs to a non-sink enum category (claim_field_role,
authority_kind, guard_kind, ...). Such sinks are mis-tags — e.g. a credential
*parser* tagged as a sink with role ``report_data`` — and letting them through
makes TWE-FLOW-001 fire on base64/protobuf parsing instead of a real security
decision (a confirmed false positive observed on fabric-private-chaincode).
"""

from __future__ import annotations

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.generator.annotation_facts import generate_facts


def _sink(name: str, role: str) -> TrustAnnotation:
    return TrustAnnotation(
        id=f"sink-{name}", kind=AnnotationKind.SINK, role=role,
        name=name, file="main.go", line=1, resolution_status=ResolutionStatus.ACCEPTED,
        resolved_file="main.go", resolved_line=1,
    )


def test_claim_field_role_sink_is_not_emitted() -> None:
    ann = TrustAnnotationSet(repo="x", annotations=[_sink("ConvertCredentials", "report_data")])
    facts = generate_facts(ann, "go")
    sink_block = facts.split("predicate isTrustSink")[1].split("}")[0]
    assert "none()" in sink_block, "claim-field-role sink must be suppressed"
    assert "ConvertCredentials" not in sink_block


def test_genuine_sink_role_is_emitted() -> None:
    ann = TrustAnnotationSet(repo="x", annotations=[_sink("deriveKey", "key_derivation_input")])
    facts = generate_facts(ann, "go")
    sink_block = facts.split("predicate isTrustSink")[1].split("}")[0]
    assert "deriveKey" in sink_block, "genuine sink role (not in any non-sink category) must be emitted"
    assert "none()" not in sink_block


def test_observable_sink_role_is_emitted() -> None:
    # leakage sinks use observable_sink_role values (log_output etc.)
    ann = TrustAnnotationSet(repo="x", annotations=[_sink("writeLog", "log_output")])
    facts = generate_facts(ann, "go")
    sink_block = facts.split("predicate isTrustSink")[1].split("}")[0]
    assert "writeLog" in sink_block


def test_authority_kind_sink_is_not_emitted() -> None:
    # an authority point mis-tagged as a sink must also be suppressed
    ann = TrustAnnotationSet(repo="x", annotations=[_sink("releaseKey", "key_release")])
    facts = generate_facts(ann, "go")
    sink_block = facts.split("predicate isTrustSink")[1].split("}")[0]
    assert "releaseKey" not in sink_block
