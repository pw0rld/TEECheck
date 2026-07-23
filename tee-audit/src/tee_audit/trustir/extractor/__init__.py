"""TrustIR iteration-3 IRIS extraction (enumerate-then-classify).

CodeQL enumerates the real API surface
(:func:`~tee_audit.trustir.codeql_fetch.run_fetch_queries`); the LLM classifies a
subset into role-tagged annotations
(:func:`~tee_audit.trustir.extractor.enumerate_classify.classify_repo`).
"""

from __future__ import annotations

from tee_audit.trustir.extractor.enumerate_classify import (
    classify_repo,
    extract_repo,
)

__all__ = [
    "classify_repo",
    "extract_repo",
]
