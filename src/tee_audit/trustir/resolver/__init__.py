"""Annotation resolver package (iteration 2)."""

from __future__ import annotations

from tee_audit.trustir.resolver.resolver import SymbolIndex, resolve_annotation, resolve_set
from tee_audit.trustir.resolver.symbol_index import find_call_sites, index_function_defs

__all__ = [
    "SymbolIndex",
    "resolve_annotation",
    "resolve_set",
    "index_function_defs",
    "find_call_sites",
]
