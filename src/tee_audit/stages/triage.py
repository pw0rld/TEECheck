"""Stage 5a: Quick Triage — grade SARIF results and cluster by invariant.

Deterministic grading — no LLM involved.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from tee_audit.contracts import Stage5aInput, Stage5aOutput
from tee_audit.models.finding import Confidence, TrustPathTier
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

# Directories/patterns that are NOT production attack surface
_TEST_PATH_PATTERNS = re.compile(
    r"(?:^|/)(?:test|tests|testing|examples|benches|bin|cli|wasm|target|build|dist|docs?)(?:/|$)",
    re.IGNORECASE,
)

# Message patterns that indicate data-container false positives
_DATA_CONTAINER_PATTERNS = re.compile(
    r"(?:struct|field|fields?|container)\s+(?:lacks?\s+)?(?:inline\s+)?validation",
    re.IGNORECASE,
)

# TEE-related keywords for relevance confidence scoring
_TEE_KEYWORDS = re.compile(
    r"(?:enclave|attestation|attest|quote|measurement|sealing|sealed|unseal|"
    r"MRENCLAVE|MRSIGNER|PCR|RTMR|ECALL|OCALL|epoch|rollback|checkpoint|"
    r"report_data|TCB|DCAP|SGX|TDX|SEV|SNP|Nitro|TrustZone|OP-TEE|"
    r"AESM|tdx_attest|sgx_attest|dcap.qvl|key.provider|CVM|"
    r"mrtd|td.report|guest.report|launch.digest|isv_svn|cpusvn|"
    r"qe.identity|collateral|pccs|tcb.info)",
    re.IGNORECASE,
)


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

    # Default to needs agent validation
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


def _classify_tee_relevance(invariant_id: str, message: str, code_location: str) -> tuple[bool, str]:
    """Classify TEE relevance using invariant match + keyword presence.

    Returns (is_tee_relevant, tee_confidence) where confidence is "high", "low", or "none".
    """
    if invariant_id == "UNMATCHED":
        # No invariant match — likely generic CodeQL finding
        # Still check for TEE keywords as a secondary signal
        combined = f"{message or ''} {code_location}"
        if _TEE_KEYWORDS.search(combined):
            return True, "low"
        return False, "none"

    # Invariant-matched: TEE-relevant by construction (after Stage 2 rewrite)
    combined = f"{message or ''} {code_location}"
    if _TEE_KEYWORDS.search(combined):
        return True, "high"
    return True, "low"


def run_triage(input_data: Stage5aInput) -> Stage5aOutput:
    """Run Stage 5a: Quick triage of SARIF results.

    Grades results, clusters by invariant, separates positive guards.
    """
    logger.info("Stage 5a: Triaging SARIF results from %s", input_data.sarif_path)

    doc = parse_sarif(input_data.sarif_path)
    results = extract_results(doc)

    graded_findings: list[GradedFinding] = []
    positive_guards: list[PositiveGuard] = []
    skipped_test = 0
    skipped_noise = 0

    for i, result in enumerate(results):
        grade, confidence = _classify_confidence(result.rule_id, result.message)
        invariant_id = _match_invariant(result.rule_id, input_data.invariants)

        loc = result.locations[0] if result.locations else None
        code_location = f"{loc.file}:{loc.line}" if loc else "unknown"

        # Pre-filter: skip test/example/benchmark/CLI files
        if code_location != "unknown" and _TEST_PATH_PATTERNS.search(code_location):
            skipped_test += 1
            continue

        # Pre-filter: skip data-container noise patterns
        if _DATA_CONTAINER_PATTERNS.search(result.message):
            skipped_noise += 1
            continue

        loc = result.locations[0] if result.locations else None
        code_location = f"{loc.file}:{loc.line}" if loc else "unknown"
        snippet = loc.snippet if loc else None

        # Check if this is a positive guard
        is_guard = any(re.search(p, result.rule_id, re.IGNORECASE) for p in GUARD_RULE_PATTERNS)
        if is_guard and grade in (Grade.CONFIRMED_ISSUE, Grade.LIKELY_ISSUE):
            positive_guards.append(PositiveGuard(
                id=f"PG-{len(positive_guards) + 1:02d}",
                invariant_refs=[invariant_id],
                trust_path_tier=TrustPathTier.CORE,
                description=result.message[:500],
                code_evidence=code_location,
                completeness_status="complete" if confidence == Confidence.CONFIRMED else "partial",
            ))
            continue

        tee_rel, tee_conf = _classify_tee_relevance(invariant_id, result.message, code_location)
        graded_findings.append(GradedFinding(
            sarif_result_id=f"SARIF-{i + 1:03d}",
            invariant_id=invariant_id,
            grade=grade,
            confidence=confidence,
            code_location=code_location,
            snippet=snippet,
            message=result.message,
            is_tee_relevant=tee_rel,
            tee_confidence=tee_conf,
        ))

    logger.info(
        "Stage 5a complete: %d graded findings, %d positive guards (skipped %d test, %d noise)",
        len(graded_findings),
        len(positive_guards),
        skipped_test,
        skipped_noise,
    )
    return Stage5aOutput(graded_findings=graded_findings, positive_guards=positive_guards)
