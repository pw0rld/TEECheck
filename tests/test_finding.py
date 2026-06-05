"""Tests for Finding model extensions (TraceHop, trust boundary fields)."""

from tee_audit.models.finding import (
    CodeLocation,
    Finding,
    Severity,
    Confidence,
    TrustPathTier,
    TaxonomyCategory,
    TEEDimension,
    TraceHop,
)


def test_trace_hop_model():
    hop = TraceHop(
        source_zone="untrusted",
        crossing_point="src/enclave.rs:42: ecall_process",
        sink_zone="trusted",
        verification_status="missing",
        description="Host input enters enclave without validation",
    )
    assert hop.source_zone == "untrusted"
    assert hop.verification_status == "missing"


def test_finding_with_trace():
    f = Finding(
        id="V-01",
        invariant_id="INV-01",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        title="Unvalidated ECALL input",
        attack_path=["1. Craft malicious input", "2. Call ECALL with payload"],
        code_locations=[CodeLocation(file="src/enclave.rs", line=42)],
        remediation="Validate all ECALL inputs",
        trust_path_tier=TrustPathTier.CORE,
        tee_category=TaxonomyCategory.TRUST_BOUNDARY_FLOW,
        tee_dimension=TEEDimension.INCORRECT_USAGE,
        is_tee_relevant=True,
        trust_boundary_trace=[
            TraceHop(
                source_zone="untrusted",
                crossing_point="src/enclave.rs:42: ecall_process",
                sink_zone="trusted",
                verification_status="missing",
            ),
        ],
        trust_boundary_prose="Host-supplied data enters enclave processing without bounds checking.",
    )
    assert f.trust_boundary_trace is not None
    assert len(f.trust_boundary_trace) == 1
    assert f.trust_boundary_trace[0].sink_zone == "trusted"
    assert f.trust_boundary_prose != ""


def test_finding_without_trace():
    f = Finding(
        id="V-02",
        invariant_id="INV-02",
        severity=Severity.INFO,
        confidence=Confidence.LIKELY,
        title="Generic finding",
        attack_path=["Step 1"],
        code_locations=[],
        remediation="N/A",
        trust_path_tier=TrustPathTier.PERIPHERAL,
        is_tee_relevant=False,
    )
    assert f.trust_boundary_trace is None
    assert f.trust_boundary_prose == ""


def test_finding_serialization_roundtrip():
    f = Finding(
        id="V-03",
        invariant_id="INV-01",
        severity=Severity.MEDIUM,
        confidence=Confidence.LIKELY,
        title="Test finding",
        attack_path=["Step 1"],
        code_locations=[CodeLocation(file="src/main.rs", line=10)],
        remediation="Fix it",
        trust_path_tier=TrustPathTier.ADJACENT,
        trust_boundary_trace=[
            TraceHop(
                source_zone="trusted",
                crossing_point="src/main.rs:10",
                sink_zone="untrusted",
                verification_status="present",
            ),
        ],
        trust_boundary_prose="Test prose.",
    )
    data = f.model_dump_json()
    restored = Finding.model_validate_json(data)
    assert restored.trust_boundary_trace is not None
    assert len(restored.trust_boundary_trace) == 1
    assert restored.trust_boundary_prose == "Test prose."
