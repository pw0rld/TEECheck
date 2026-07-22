"""Resolution primitives, the BindResult container, and the hallucination guard.

A ``Resolution`` records the outcome of checking a single fact (claim producer,
claim field, authority point, guard, evidence span). Because the IR models are
not all declared with ``extra="allow"``, per-fact resolutions are stored in an
external dict on :class:`BindResult` (keyed by fact id) rather than stamped onto
each model. The resolved IR carries a top-level ``resolution_summary`` only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from tee_audit.trustir.binder.symbol_index import find_name_occurrences, last_segment, read_lines
from tee_audit.trustir.models import Selector

ResolutionStatus = Literal["resolved", "rejected", "unresolved"]


@dataclass
class Resolution:
    """Outcome of resolving one fact against the repo on disk."""

    fact_id: str
    status: ResolutionStatus
    reason: str | None = None
    node: dict[str, Any] | None = None


@dataclass
class BindResult:
    """Result of binding a TrustIR candidate to a repo root.

    ``resolutions`` maps fact id -> :class:`Resolution` for every fact the
    binder examined (producers, claim fields, authority points + subjects,
    guards, evidence spans). ``resolved`` is the input IR annotated only with a
    top-level ``resolution_summary``.
    """

    resolved: BaseModel  # the input IR
    rejected: list[dict[str, Any]] = field(default_factory=list)
    resolutions: dict[str, Resolution] = field(default_factory=dict)
    coverage: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# File-level resolution
# --------------------------------------------------------------------------- #


def resolve_file(file: str, repo_root: Path) -> tuple[Path | None, str | None]:
    """Resolve ``file`` under ``repo_root``. Returns (path, reason).

    Returns ``(None, "file_not_found")`` if the path escapes the repo or does not
    exist as a file. On success returns ``(absolute_path, None)``.
    """
    root_abs = repo_root.resolve()
    candidate = root_abs / file
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None, "file_not_found"
    # Escape check: resolved path must be inside repo_root.
    try:
        resolved.relative_to(root_abs)
    except ValueError:
        return None, "file_not_found"
    if not resolved.is_file():
        return None, "file_not_found"
    return resolved, None


# --------------------------------------------------------------------------- #
# Symbol resolution (Selector form)
# --------------------------------------------------------------------------- #


def resolve_selector(
    selector: Selector,
    repo_root: Path,
    fact_id: str,
    tolerance: int = 2,
) -> Resolution:
    """Resolve a :class:`Selector` against the repo.

    Requires ``selector.file`` and ``selector.qualified_name``. If either is
    missing the fact is ``unresolved``.
    """
    file_rel = selector.file
    qname = selector.qualified_name
    if not file_rel or not qname:
        return Resolution(
            fact_id=fact_id,
            status="unresolved",
            reason="missing_selector",
        )

    path, reason = resolve_file(file_rel, repo_root)
    if path is None:
        return Resolution(fact_id=fact_id, status="rejected", reason=reason)

    lines = read_lines(path)
    nlines = len(lines)
    name = last_segment(qname)
    occurrences = find_name_occurrences(lines, name)

    if not occurrences:
        return Resolution(fact_id=fact_id, status="rejected", reason="symbol_not_found")

    claimed_line = selector.line
    if claimed_line is not None:
        if claimed_line < 1 or claimed_line > nlines:
            return Resolution(fact_id=fact_id, status="rejected", reason="out_of_range")

        # Nearest occurrence to the claimed line.
        nearest = min(occurrences, key=lambda ln: abs(ln - claimed_line))
        if abs(nearest - claimed_line) <= tolerance:
            matched_line = nearest
            node: dict[str, Any] = {
                "file": file_rel,
                "line": matched_line,
                "qualified_name": qname,
                "matched_line_text": lines[matched_line - 1],
                "line_confirmed": matched_line == claimed_line,
            }
            if matched_line != claimed_line:
                node["line_drift"] = claimed_line - matched_line
            return Resolution(fact_id=fact_id, status="resolved", node=node)
        return Resolution(
            fact_id=fact_id,
            status="rejected",
            reason="out_of_line",
        )

    # No claimed line: resolved if name is present.
    return Resolution(
        fact_id=fact_id,
        status="resolved",
        node={
            "file": file_rel,
            "line": occurrences[0],
            "qualified_name": qname,
            "matched_line_text": lines[occurrences[0] - 1],
            "line_confirmed": False,
        },
    )


# --------------------------------------------------------------------------- #
# String-selector resolution (field-access like "receipt.publicKey")
# --------------------------------------------------------------------------- #


def resolve_field_selector(
    selector_str: str,
    file_rel: str | None,
    repo_root: Path,
    fact_id: str,
    fallback_file: str | None = None,
) -> Resolution:
    """Resolve a field-access string selector against a file.

    ``token`` = last ``.``-separated segment. The token must occur in the file.
    Uses ``file_rel`` if given, else ``fallback_file``.
    """
    target_file = file_rel or fallback_file
    if not target_file:
        return Resolution(
            fact_id=fact_id,
            status="unresolved",
            reason="missing_file_for_field",
        )
    path, reason = resolve_file(target_file, repo_root)
    if path is None:
        return Resolution(fact_id=fact_id, status="rejected", reason=reason)

    lines = read_lines(path)
    token = last_segment(selector_str)
    occurrences = find_name_occurrences(lines, token)
    if not occurrences:
        return Resolution(fact_id=fact_id, status="rejected", reason="field_not_found")

    return Resolution(
        fact_id=fact_id,
        status="resolved",
        node={
            "file": target_file,
            "line": occurrences[0],
            "token": token,
            "matched_line_text": lines[occurrences[0] - 1],
        },
    )


# --------------------------------------------------------------------------- #
# Evidence span resolution
# --------------------------------------------------------------------------- #


def resolve_evidence_span(span: Any, repo_root: Path) -> Resolution:
    """Verify an evidence span's file exists and its line range is in bounds."""
    file_rel = span.file
    path, reason = resolve_file(file_rel, repo_root)
    if path is None:
        return Resolution(fact_id=span.id, status="rejected", reason=reason)

    lines = read_lines(path)
    nlines = len(lines)
    start, end = span.start_line, span.end_line
    if start < 1 or end < start or end > nlines:
        return Resolution(fact_id=span.id, status="rejected", reason="bad_span")

    return Resolution(
        fact_id=span.id,
        status="resolved",
        node={
            "file": file_rel,
            "start_line": start,
            "end_line": end,
            "nlines": nlines,
        },
    )


# --------------------------------------------------------------------------- #
# Zero-hallucination invariant
# --------------------------------------------------------------------------- #


def assert_no_hallucinated_resolutions(result: BindResult, repo_root: Path) -> None:
    """Re-check that every ``resolved`` fact still has a backing file + name match.

    Raises ``AssertionError`` on any violation. Reads from
    :attr:`BindResult.resolutions` so callers may mutate the IR (e.g. corrupt a
    selector path in a test) and still have the invariant re-checked against the
    *original* resolution records.
    """
    ir = result.resolved
    failures: list[str] = []

    def _check_file_and_token(fact_id: str, file_rel: str, token: str | None) -> None:
        path, reason = resolve_file(file_rel, repo_root)
        if path is None:
            failures.append(f"{fact_id}: backing file missing ({reason})")
            return
        if token is not None:
            lines = read_lines(path)
            if not find_name_occurrences(lines, token):
                failures.append(f"{fact_id}: token '{token}' not found in {file_rel}")

    # Producers.
    for producer in getattr(ir, "claim_producers", []):
        res = result.resolutions.get(producer.id)
        if res and res.status == "resolved":
            sel = producer.selector
            _check_file_and_token(producer.id, sel.file, last_segment(sel.qualified_name))

    # Claim fields.
    for cf in getattr(ir, "claim_fields", []):
        res = result.resolutions.get(cf.id)
        if res and res.status == "resolved":
            node = res.node or {}
            file_rel = node.get("file")
            token = node.get("token")
            if file_rel and token:
                _check_file_and_token(cf.id, file_rel, token)

    # Authority points.
    for ap in getattr(ir, "authority_points", []):
        res = result.resolutions.get(ap.id)
        if res and res.status == "resolved":
            sel = ap.selector
            _check_file_and_token(ap.id, sel.file, last_segment(sel.qualified_name))

    # Guards (optional selector).
    for g in getattr(ir, "guards", []):
        res = result.resolutions.get(g.id)
        if res and res.status == "resolved" and g.selector is not None:
            sel = g.selector
            _check_file_and_token(g.id, sel.file, last_segment(sel.qualified_name))

    # Evidence spans.
    for span in getattr(ir, "evidence_spans", []):
        res = result.resolutions.get(span.id)
        if res and res.status == "resolved":
            _check_file_and_token(span.id, span.file, None)

    if failures:
        raise AssertionError("hallucinated resolutions:\n  " + "\n  ".join(failures))
