"""TrustIR: a deterministic TEE-usage weakness IR + binder/CodeQL/solver pipeline.

This sub-package implements the ``web3_tee_trustir_docs`` engineering design inside
tee-audit. The LLM only performs semantic extraction into TrustIR candidate JSON; a
deterministic binder resolves it, a generator emits CodeQL facts (no vulnerability
logic), prewritten CodeQL query modules check obligations, and a solver classifies
findings conservatively.

Public entry points are re-exported from :mod:`tee_audit.trustir`.
"""

from __future__ import annotations

from tee_audit.trustir.loader import load_trustir
from tee_audit.trustir.models import TrustIR
from tee_audit.trustir.spec import bundled_spec_dir, bundled_spec_path
from tee_audit.trustir.validator import ValidationIssue, validate_trustir, validate_trustir_file

__all__ = [
    "TrustIR",
    "load_trustir",
    "validate_trustir",
    "validate_trustir_file",
    "ValidationIssue",
    "bundled_spec_dir",
    "bundled_spec_path",
]
