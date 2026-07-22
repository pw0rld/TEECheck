"""Tests for auto-escalation logic in Stage 5b."""

from tee_audit.models.finding import (
    Finding,
    Severity,
    Confidence,
    TrustPathTier,
    CodeLocation,
)
from tee_audit.stages.deep_verify import _identify_weak_clusters


def _make_finding(severity: Severity, dismissed: bool = False) -> Finding:
    return Finding(
        id="V-01",
        invariant_id="INV-01",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        title="Test finding",
        attack_path=["Step 1"],
        code_locations=[CodeLocation(file="src/main.rs", line=10)],
        remediation="Fix it",
        trust_path_tier=TrustPathTier.CORE,
        dismissed=dismissed,
    )


def test_identify_weak_clusters_all_info():
    """Cluster with only Info findings is weak."""
    results = {
        "INV-01::src/main.rs": (
            [_make_finding(Severity.INFO)],
            [],
        ),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" in weak


def test_identify_weak_clusters_more_unknowns_than_findings():
    """Cluster with more unknowns than findings is weak."""
    from tee_audit.models.unknown import Unknown
    results = {
        "INV-01::src/main.rs": (
            [_make_finding(Severity.MEDIUM)],
            [
                Unknown(id="U-01", title="Test", what_was_checked="x", why_uncertain="y", recommended_steps=["z"]),
                Unknown(id="U-02", title="Test2", what_was_checked="a", why_uncertain="b", recommended_steps=["c"]),
            ],
        ),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" in weak


def test_identify_weak_clusters_dismissed_only():
    """Cluster with only dismissed findings + unknowns is weak."""
    from tee_audit.models.unknown import Unknown
    results = {
        "INV-01::src/main.rs": (
            [_make_finding(Severity.HIGH, dismissed=True)],
            [Unknown(id="U-01", title="Test", what_was_checked="x", why_uncertain="y", recommended_steps=["z"])],
        ),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" in weak


def test_identify_weak_clusters_strong_not_weak():
    """Cluster with active Medium+ findings is NOT weak."""
    results = {
        "INV-01::src/main.rs": (
            [_make_finding(Severity.MEDIUM), _make_finding(Severity.HIGH)],
            [],
        ),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" not in weak


def test_identify_weak_clusters_empty_not_weak():
    """Empty cluster is not considered weak."""
    results = {
        "INV-01::src/main.rs": ([], []),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" not in weak


def test_identify_weak_clusters_mixed_severity():
    """Cluster with at least one Low+ active finding is not weak."""
    results = {
        "INV-01::src/main.rs": (
            [_make_finding(Severity.INFO), _make_finding(Severity.LOW)],
            [],
        ),
    }
    weak = _identify_weak_clusters(results)
    assert "INV-01::src/main.rs" not in weak
