"""Per-stage typed input/output contracts for the pipeline."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from tee_audit.models.finding import Finding
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant
from tee_audit.models.report import Report
from tee_audit.models.triage import GradedFinding, PositiveGuard
from tee_audit.models.unknown import Unknown


# Stage 0: Fingerprint
class Stage0Output(BaseModel):
    fingerprint: Fingerprint


# Stage 1: Dossier
class Stage1Input(BaseModel):
    repo_path: Path
    fingerprint: Fingerprint


class Stage1Output(BaseModel):
    dossier: str
    sections: dict[str, str]


# Stage 2: Invariants
class Stage2Input(BaseModel):
    fingerprint: Fingerprint
    dossier: str


class Stage2Output(BaseModel):
    invariants: list[Invariant]


# Stage 3: Analysis Matrix
class Stage3Input(BaseModel):
    invariants: list[Invariant]


class Stage3Output(BaseModel):
    matrix_markdown: str
    matrix_tsv: str


# Stage 4: CodeQL Operations
class Stage4Input(BaseModel):
    repo_path: Path
    invariants: list[Invariant]


class Stage4Output(BaseModel):
    db_path: Path
    sarif_path: Path
    result_count: int


# Stage 5a: Quick Triage
class Stage5aInput(BaseModel):
    sarif_path: Path
    invariants: list[Invariant]


class Stage5aOutput(BaseModel):
    graded_findings: list[GradedFinding]
    positive_guards: list[PositiveGuard]


# Stage 5b: Deep Verification
class Stage5bInput(BaseModel):
    graded_findings: list[GradedFinding]
    invariants: list[Invariant]
    repo_path: Path


class Stage5bOutput(BaseModel):
    verified_findings: list[Finding]
    unknowns: list[Unknown]


# Stage 6: Report Assembly
class Stage6Input(BaseModel):
    fingerprint: Fingerprint
    invariants: list[Invariant]
    findings: list[Finding]
    positive_guards: list[PositiveGuard]
    unknowns: list[Unknown]


class Stage6Output(BaseModel):
    report: Report
    report_path: Path
