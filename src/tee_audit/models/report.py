"""Report data model — output of Stage 6."""

from __future__ import annotations

from pydantic import BaseModel

from tee_audit.models.finding import Finding, Severity, TrustPathTier
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant
from tee_audit.models.triage import PositiveGuard
from tee_audit.models.unknown import Unknown


class DashboardEntry(BaseModel):
    """A single cell in the severity × trust-path-tier dashboard matrix."""

    severity: Severity
    trust_path_tier: TrustPathTier
    count: int


class Report(BaseModel):
    """Complete audit report produced by Stage 6."""

    project_name: str
    fingerprint: Fingerprint | None = None
    invariants: list[Invariant] = []
    findings: list[Finding] = []
    positive_guards: list[PositiveGuard] = []
    unknowns: list[Unknown] = []
    dashboard: list[DashboardEntry] = []
    executive_summary: str = ""
