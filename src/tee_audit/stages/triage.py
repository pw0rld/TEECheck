"""Stage 5a: Quick Triage — grade SARIF results and cluster by invariant.

Deterministic grading — no LLM involved.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from tee_audit.contracts import Stage5aInput, Stage5aOutput
from tee_audit.models.finding import Confidence
from tee_audit.models.triage import Grade, GradedFinding, PositiveGuard
from tee_audit.utils.sarif import parse_sarif, extract_results

logger = logging.getLogger(__name__)

# Rules that typically indicate positive guards rather than findings
GUARD_RULE_PATTERNS = [
    r"guard",
    r"check",
    r"verify",
    r"validate",
    r"protect",
]


def _classify_confidence(rule_id: str, message: str) -> tuple[Grade, Confidence]:
    """Classify a SARIF result into a grade and confidence level.

    Uses rule-id heuristics and message content. Deterministic.
    """
    msg_lower = message.lower()

    # Check if this is a positive guard result
    if any(re.search(p, rule_id, re.IGNORECASE) for p in GUARD_RULE_PATTERNS):
        if "complete" in msg_lower or "present" in msg_lower or "verified" in msg_lower:
            return Grade.CONFIRMED_ISSUE, Confidence.CONFIRMED

    # Severity-based grading
    if "error" in msg_lower or "critical" in msg_lower:
        return Grade.LIKELY_ISSUE, Confidence.LIKELY
    if "warning" in msg_lower:
        return Grade.LIKELY_ISSUE, Confidence.LIKELY
    if "note" in msg_lower or "info" in msg_lower:
        return Grade.WEAK_SIGNAL, Confidence.WEAK

    # Default to needs manual validation
    return Grade.NEEDS_MANUAL_VALIDATION, Confidence.NEEDS_MANUAL


def _match_invariant(rule_id: str, invariants: list) -> str:
    """Match a SARIF result to an invariant by rule ID naming convention.

    Convention: rule IDs include the invariant family or ID.
    Falls back to "UNMATCHED" if no match found.
    """
    rule_lower = rule_id.lower()

    # Try direct ID match (e.g., "inv-03-binding" -> "INV-03")
    inv_match = re.search(r"inv[-_]?(\d+)", rule_lower, re.IGNORECASE)
    if inv_match:
        inv_id = f"INV-{int(inv_match.group(1)):02d}"
        for inv in invariants:
            if inv.id == inv_id:
                return inv.id

    # Try family match
    for inv in invariants:
        if inv.family.value.lower() in rule_lower:
            return inv.id

    # Assign to first invariant if only one exists
    if len(invariants) == 1:
        return invariants[0].id

    return "UNMATCHED"


def run_triage(input_data: Stage5aInput) -> Stage5aOutput:
    """Run Stage 5a: Quick triage of SARIF results.

    Grades results, clusters by invariant, separates positive guards.
    """
    logger.info("Stage 5a: Triaging SARIF results from %s", input_data.sarif_path)

    doc = parse_sarif(input_data.sarif_path)
    results = extract_results(doc)

    graded_findings: list[GradedFinding] = []
    positive_guards: list[PositiveGuard] = []

    for i, result in enumerate(results):
        grade, confidence = _classify_confidence(result.rule_id, result.message)
        invariant_id = _match_invariant(result.rule_id, input_data.invariants)

        loc = result.locations[0] if result.locations else None
        code_location = f"{loc.file}:{loc.line}" if loc else "unknown"
        snippet = loc.snippet if loc else None

        # Check if this is a positive guard
        is_guard = any(re.search(p, result.rule_id, re.IGNORECASE) for p in GUARD_RULE_PATTERNS)
        if is_guard and grade in (Grade.CONFIRMED_ISSUE, Grade.LIKELY_ISSUE):
            positive_guards.append(PositiveGuard(
                id=f"PG-{len(positive_guards) + 1:02d}",
                invariant_refs=[invariant_id],
                trust_path_tier="core",
                description=result.message[:200],
                code_evidence=code_location,
                completeness_status="complete" if confidence == Confidence.CONFIRMED else "partial",
            ))
            continue

        graded_findings.append(GradedFinding(
            sarif_result_id=f"SARIF-{i + 1:03d}",
            invariant_id=invariant_id,
            grade=grade,
            confidence=confidence,
            code_location=code_location,
            snippet=snippet,
            message=result.message[:500],
        ))

    logger.info(
        "Stage 5a complete: %d graded findings, %d positive guards",
        len(graded_findings),
        len(positive_guards),
    )
    return Stage5aOutput(graded_findings=graded_findings, positive_guards=positive_guards)
