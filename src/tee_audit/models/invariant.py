"""Invariant data model — output of Stage 2."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class InvariantFamily(str, Enum):
    """Analysis families for TEE×Web3 invariants."""

    FLOW = "Flow"
    GUARD = "Guard"
    BINDING = "Binding"
    STATE = "State"
    CONFIG = "Config"


class Invariant(BaseModel):
    """A security invariant extracted from the repository's trust architecture."""

    id: str  # e.g., "INV-01"
    description: str
    trust_path: str
    family: InvariantFamily
    sources: list[str]
    sinks: list[str]
    guards: list[str]
    failure_modes: list[str]
    codeql_expressible: bool
