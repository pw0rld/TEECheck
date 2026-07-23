"""Finding data model — output of Stage 5b."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    WEAK = "Weak"
    NEEDS_MANUAL = "NeedsManual"


class TrustPathTier(str, Enum):
    CORE = "core"
    ADJACENT = "adjacent"
    PERIPHERAL = "peripheral"


class TaxonomyCategory(str, Enum):
    TRUST_BOUNDARY_FLOW = "Trust Boundary Flow"
    VERIFICATION_GAP = "Verification Gap"
    BINDING_WEAKNESS = "Binding Weakness"
    STATE_CONTINUITY = "State Continuity"
    CONFIGURATION_INTEGRITY = "Configuration Integrity"
    DESIGN_APPROPRIATENESS = "Design Appropriateness"
    OUTPUT_METADATA_LEAKAGE = "Output & Metadata Leakage"


class TEEDimension(str, Enum):
    INCORRECT_USAGE = "incorrect_usage"
    INAPPROPRIATE_DESIGN = "inappropriate_design"


class CodeLocation(BaseModel):
    """A specific code location referenced in a finding."""

    file: str
    line: int | None = None
    snippet: str | None = None


class TraceHop(BaseModel):
    """One hop in a trust boundary crossing trace."""

    source_zone: str  # "trusted" or "untrusted"
    crossing_point: str  # file:line or function name
    sink_zone: str  # "trusted" or "untrusted"
    verification_status: str  # "present" or "missing"
    description: str = ""
    # Enriched chain detail for cross-file rendering
    caller_function: str = ""
    callee_name: str = ""
    callee_module: str = ""
    file: str = ""
    line: int | None = None
    crosses_boundary: bool = False
    zone_source: str = "unknown"  # "heuristic" | "manifest" | "llm_inferred"


class Finding(BaseModel):
    """A verified security finding from deep verification (Stage 5b)."""

    id: str  # e.g., "V-01"
    invariant_id: str
    severity: Severity
    confidence: Confidence
    title: str
    attack_path: list[str]  # numbered POC steps
    code_locations: list[CodeLocation]
    remediation: str = ""
    trust_path_tier: TrustPathTier = TrustPathTier.CORE
    cwe_id: str | None = None  # e.g., "CWE-345"
    impact: str = ""  # what happens if exploited
    root_cause: str = ""  # why the vulnerability exists
    preconditions: list[str] = []  # what must be true for exploitation
    dismissed: bool = False  # true if adversarial review identified false positive
    dismissal_reason: str = ""  # why the finding was dismissed
    tee_category: TaxonomyCategory | None = None
    tee_dimension: TEEDimension | None = None
    is_tee_relevant: bool = True
    trust_boundary_trace: list[TraceHop] | None = None
    trust_boundary_prose: str = ""
