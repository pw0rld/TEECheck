"""Locators for the spec files bundled inside the tee-audit package.

``tee-audit`` is self-contained: the taxonomy, enum registry, TWE catalog, and
TrustIR JSON schema are bundled under ``tee_audit/trustir/spec/`` rather than
read from the external ``web3_tee_trustir_docs`` guideline directory.
"""

from __future__ import annotations

from pathlib import Path

_BUNDLED_SPEC_DIR = Path(__file__).resolve().parent / "spec"


def bundled_spec_dir() -> Path:
    """Directory containing the bundled spec YAML + JSON files."""
    return _BUNDLED_SPEC_DIR


def bundled_spec_path(name: str) -> Path:
    """Path to a bundled spec file by name (e.g. ``trustir.schema.json``)."""
    return _BUNDLED_SPEC_DIR / name


__all__ = ["bundled_spec_dir", "bundled_spec_path"]
