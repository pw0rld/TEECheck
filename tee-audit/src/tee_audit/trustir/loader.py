"""TrustIR loader: read candidate/resolved JSON into typed models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tee_audit.trustir.models import TrustIR


def parse_trustir(data: dict[str, Any]) -> TrustIR:
    """Validate a parsed dict into a :class:`TrustIR` instance.

    Raises ``pydantic.ValidationError`` on schema/enum violations.
    """
    return TrustIR.model_validate(data)


def load_trustir(path: str | Path) -> TrustIR:
    """Load a TrustIR JSON file from disk into a typed :class:`TrustIR`."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_trustir(data)


def dump_trustir(ir: TrustIR, path: str | Path) -> None:
    """Write a TrustIR instance back to disk as JSON."""
    Path(path).write_text(ir.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")


__all__ = ["parse_trustir", "load_trustir", "dump_trustir"]
