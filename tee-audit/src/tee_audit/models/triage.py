"""Triage data models — intermediate types for Stage 5a."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from tee_audit.models.finding import Confidence, TrustPathTier


class Grade(str, Enum):
    """Triage grade for SARIF results."""

    CONFIRMED_ISSUE = "ConfirmedIssue"
    LIKELY_ISSUE = "LikelyIssue"
    WEAK_SIGNAL = "WeakSignal"
    NEEDS_MANUAL_VALIDATION = "NeedsManualValidation"


class GradedFinding(BaseModel):
    """A SARIF result with an assigned triage grade."""

    sarif_result_id: str
    invariant_id: str
    grade: Grade
    confidence: Confidence
    code_location: str  # file:line
    snippet: str | None = None
    message: str | None = None
    is_tee_relevant: bool = True
    tee_confidence: str = "high"  # "high", "low", or "none"


class PositiveGuard(BaseModel):
    """A verified positive security guard found during triage."""

    id: str  # e.g., "PG-01"
    invariant_refs: list[str]  # e.g., ["INV-01", "INV-02"]
    trust_path_tier: TrustPathTier
    title: str = ""  # concise label, e.g. "Root CA cert chain validation"
    description: str
    code_evidence: str
    completeness_status: str  # "complete" or "partial"
