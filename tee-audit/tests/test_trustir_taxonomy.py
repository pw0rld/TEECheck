"""Tests for the shared TWE taxonomy mapping (derive_family)."""

from __future__ import annotations

from tee_audit.trustir.models import TaxonomyFamily
from tee_audit.trustir.taxonomy import derive_family


def test_derive_family_each_token() -> None:
    assert derive_family("TWE-FLOW-001") == TaxonomyFamily.FLOW
    assert derive_family("TWE-GUARD-002") == TaxonomyFamily.GUARD
    assert derive_family("TWE-BIND-003") == TaxonomyFamily.BINDING
    assert derive_family("TWE-STATE-001") == TaxonomyFamily.STATE
    assert derive_family("TWE-CONFIG-002") == TaxonomyFamily.CONFIG
    assert derive_family("TWE-LEAK-002") == TaxonomyFamily.LEAKAGE


def test_derive_family_unknown_token_falls_back_to_design() -> None:
    assert derive_family("TWE-NOPE-009") == TaxonomyFamily.DESIGN
    assert derive_family("garbage") == TaxonomyFamily.DESIGN
