"""TrustIR validator: schema (via pydantic) + cross-field semantic checks.

The pydantic models in :mod:`tee_audit.trustir.models` enforce the JSON schema and
the allowed enum values from ``enum_registry.yml``. This module adds cross-field
consistency checks (referential integrity of ids, TWE-family coherence) and reports
issues in a structured form without raising, so callers can collect all problems.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from tee_audit.trustir.models import TaxonomyFamily, TrustIR

# Map the token inside a TWE id (e.g. "TWE-BIND-001" -> "BIND") to a family.
_TWE_TOKEN_TO_FAMILY: dict[str, TaxonomyFamily] = {
    "FLOW": TaxonomyFamily.FLOW,
    "GUARD": TaxonomyFamily.GUARD,
    "BIND": TaxonomyFamily.BINDING,
    "STATE": TaxonomyFamily.STATE,
    "CONFIG": TaxonomyFamily.CONFIG,
    "DESIGN": TaxonomyFamily.DESIGN,
    "LEAK": TaxonomyFamily.LEAKAGE,
}


class ValidationIssue(BaseModel):
    severity: str  # "error" | "warning"
    code: str
    message: str
    path: str = ""


class ValidationResult(BaseModel):
    ok: bool
    issues: list[ValidationIssue] = []

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]


def _coerce(obj: dict[str, Any] | TrustIR) -> tuple[TrustIR | None, list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    if isinstance(obj, TrustIR):
        return obj, issues
    try:
        return TrustIR.model_validate(obj), issues
    except ValidationError as exc:  # pragma: no cover - exercised by tests
        for err in exc.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            issues.append(
                ValidationIssue(
                    severity="error",
                    code=f"schema:{err.get('type', 'invalid')}",
                    message=err.get("msg", "schema validation error"),
                    path=loc,
                )
            )
        return None, issues


def validate_trustir(obj: dict[str, Any] | TrustIR) -> ValidationResult:
    """Validate a TrustIR dict/model. Returns all schema + semantic issues."""
    ir, issues = _coerce(obj)
    if ir is None:
        return ValidationResult(ok=False, issues=issues)

    span_ids = {s.id for s in ir.evidence_spans}
    producer_ids = {p.id for p in ir.claim_producers}
    authority_ids = {a.id for a in ir.authority_points}

    def _check_span_refs(holder: Any, label: str) -> None:
        for sid in getattr(holder, "evidence_span_ids", []) or []:
            if sid not in span_ids:
                issues.append(
                    ValidationIssue(
                        severity="error",
                        code="dangling:evidence_span",
                        message=f"{label} references unknown evidence span '{sid}'",
                    )
                )

    for p in ir.claim_producers:
        _check_span_refs(p, f"claim_producer:{p.id}")
    for cf in ir.claim_fields:
        _check_span_refs(cf, f"claim_field:{cf.id}")
        if cf.producer_id and cf.producer_id not in producer_ids:
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="dangling:producer",
                    message=f"claim_field:{cf.id} references unknown producer '{cf.producer_id}'",
                )
            )
    for ap in ir.authority_points:
        _check_span_refs(ap, f"authority_point:{ap.id}")

    # TWE id family coherence.
    token = ir.twe_id.upper().split("-")[1] if "-" in ir.twe_id else ""
    expected = _TWE_TOKEN_TO_FAMILY.get(token)
    if expected is not None and expected != ir.taxonomy_family:
        issues.append(
            ValidationIssue(
                severity="error",
                code="coherence:twe_family",
                message=(
                    f"twe_id '{ir.twe_id}' implies family {expected.value} but "
                    f"taxonomy_family is {ir.taxonomy_family.value}"
                ),
            )
        )

    # Obligations must reference existing authority points and agree on family.
    for ob in ir.required_obligations:
        if ob.authority_point_id not in authority_ids:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="dangling:authority_point",
                    message=f"obligation:{ob.id} references unknown authority_point '{ob.authority_point_id}'",
                )
            )
        if ob.family != ir.taxonomy_family:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="coherence:obligation_family",
                    message=(
                        f"obligation:{ob.id} family {ob.family.value} != "
                        f"taxonomy_family {ir.taxonomy_family.value}"
                    ),
                )
            )

    # A candidate without any authority point cannot produce a meaningful finding.
    if not authority_ids:
        issues.append(
            ValidationIssue(
                severity="warning",
                code="missing:authority_point",
                message="TrustIR has no authority_point; no finding can be anchored",
            )
        )

    has_errors = any(i.severity == "error" for i in issues)
    return ValidationResult(ok=not has_errors, issues=issues)


def validate_trustir_file(path: str | Path) -> ValidationResult:
    """Load JSON from disk and validate it."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ValidationResult(
            ok=False,
            issues=[ValidationIssue(severity="error", code="io", message=str(exc), path=str(p))],
        )
    return validate_trustir(data)


__all__ = ["ValidationIssue", "ValidationResult", "validate_trustir", "validate_trustir_file"]
