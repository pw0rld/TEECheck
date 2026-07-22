"""TrustIR binder: deterministically resolve LLM-proposed selectors to real code.

The binder is language-agnostic and conservative. It does not parse syntax (no
tree-sitter); it reads file lines and performs case-sensitive substring search on
the last segment of a qualified name. The zero-hallucination invariant is that
EVERY fact marked ``resolved`` has a backing file that exists on disk and whose
claimed name/token actually occurs in that file.
"""

from __future__ import annotations

from tee_audit.trustir.binder.resolver import (
    BindResult,
    Resolution,
    assert_no_hallucinated_resolutions,
)
from tee_audit.trustir.binder.trustir_binder import bind, bind_file

__all__ = [
    "bind",
    "bind_file",
    "BindResult",
    "Resolution",
    "assert_no_hallucinated_resolutions",
]
