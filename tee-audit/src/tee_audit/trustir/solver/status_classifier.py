"""Obligation status classification (design section 10.3).

Implements the exact precedence ordering of the design, plus the State/Design
manual-review cap: a State or Design obligation can never be ``confirmed`` — it
is downgraded to ``violated_candidate`` with a ``manual_review_required:<family>``
note.
"""

from __future__ import annotations

from tee_audit.trustir.models import FindingStatus

# Families subject to the manual-review cap.
_CAPPED_FAMILIES = {"State", "Design"}


def classify(raw_result: dict, suppressors: dict, coverage: dict) -> FindingStatus:
    """Classify a raw CodeQL obligation result into a final FindingStatus.

    Implements design 10.3 precedence exactly, then applies the State/Design cap.
    """
    status = _classify_base(raw_result, suppressors, coverage)

    family = raw_result.get("family")
    if status is FindingStatus.CONFIRMED and family in _CAPPED_FAMILIES:
        return FindingStatus.VIOLATED_CANDIDATE
    return status


def classify_with_note(
    raw_result: dict, suppressors: dict, coverage: dict
) -> tuple[FindingStatus, str]:
    """Like :func:`classify` but also return a note string.

    The note is ``""`` normally, or ``"manual_review_required:<family>"`` when
    the State/Design cap downgraded a confirmed finding.
    """
    base = _classify_base(raw_result, suppressors, coverage)
    family = raw_result.get("family")
    if base is FindingStatus.CONFIRMED and family in _CAPPED_FAMILIES:
        return FindingStatus.VIOLATED_CANDIDATE, f"manual_review_required:{family}"
    return base, ""


def _classify_base(
    raw_result: dict, suppressors: dict, coverage: dict
) -> FindingStatus:
    """Design 10.3 precedence, before the State/Design cap."""
    if raw_result.get("out_of_scope"):
        return FindingStatus.OUT_OF_SCOPE
    if suppressors.get("test_only"):
        return FindingStatus.TEST_ONLY
    if suppressors.get("delegated"):
        return FindingStatus.DELEGATED
    if suppressors.get("guarded_elsewhere"):
        return FindingStatus.GUARDED_ELSEWHERE
    if (
        raw_result.get("family") == "Config"
        and coverage.get("production_value_unknown")
    ):
        return FindingStatus.CONFIGURATION_DEPENDENT
    if coverage.get("missing_required_layer"):
        return FindingStatus.VIOLATED_CANDIDATE
    if raw_result.get("violation"):
        return FindingStatus.CONFIRMED
    return FindingStatus.UNRESOLVED


__all__ = ["classify", "classify_with_note"]
