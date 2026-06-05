"""Report data model — output of Stage 6."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from tee_audit.models.finding import Finding, Severity, TaxonomyCategory, TrustPathTier
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant
from tee_audit.models.triage import PositiveGuard
from tee_audit.models.unknown import Unknown


class DiagramType(str, Enum):
    ARCHITECTURE = "architecture"
    TRUST_PATH = "trust_path"
    DATA_FLOW = "data_flow"
    ATTACK_PATH = "attack_path"


class MermaidDiagram(BaseModel):
    """A Mermaid diagram embedded in the audit report."""

    diagram_type: DiagramType
    title: str
    mermaid_code: str
    text_summary: str = ""  # LLM-generated text explanation of the diagram


class TrustBoundaryRow(BaseModel):
    """A row in the trust boundary table."""

    actor: str  # who/what operates this component
    component: str  # the component or module name
    context: str  # trusted or untrusted
    boundary_type: str  # e.g., "enclave/host", "network", "storage"


class DashboardEntry(BaseModel):
    """A single cell in the severity × trust-path-tier dashboard matrix."""

    severity: Severity
    trust_path_tier: TrustPathTier
    count: int


class TaxonomySummaryEntry(BaseModel):
    """A single row in the taxonomy summary table."""

    category: TaxonomyCategory
    count: int
    finding_ids: list[str]


class Report(BaseModel):
    """Complete audit report produced by Stage 6."""

    project_name: str
    fingerprint: Fingerprint | None = None
    invariants: list[Invariant] = []
    findings: list[Finding] = []
    positive_guards: list[PositiveGuard] = []
    unknowns: list[Unknown] = []
    dashboard: list[DashboardEntry] = []
    diagrams: list[MermaidDiagram] = []
    trust_boundary_table: list[TrustBoundaryRow] = []
    trust_boundary_narrative: str = ""
    data_flow_summary: str = ""
    executive_summary: str = ""
    taxonomy_summary: list[TaxonomySummaryEntry] = []
