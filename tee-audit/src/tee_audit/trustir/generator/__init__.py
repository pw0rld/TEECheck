"""TrustIR → CodeQL fact generator + query-plan generator (US-003)."""

from __future__ import annotations

from tee_audit.trustir.generator.codeql_fact_generator import (
    generate_facts,
    generate_facts_file,
)
from tee_audit.trustir.generator.query_plan_generator import build_query_plan

__all__ = ["generate_facts", "generate_facts_file", "build_query_plan"]
