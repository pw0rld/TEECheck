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


class CodeLocation(BaseModel):
    """A specific code location referenced in a finding."""

    file: str
    line: int | None = None
    snippet: str | None = None


class Finding(BaseModel):
    """A verified security finding from deep verification (Stage 5b)."""

    id: str  # e.g., "V-01"
    invariant_id: str
    severity: Severity
    confidence: Confidence
    title: str
    attack_path: list[str]  # numbered POC steps
    code_locations: list[CodeLocation]
    remediation: str
    trust_path_tier: TrustPathTier
