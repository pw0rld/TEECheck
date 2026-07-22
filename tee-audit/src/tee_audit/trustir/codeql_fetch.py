"""Repo-wide CodeQL enumeration ("fetch") pipeline (iteration 3 — US-004).

Runs the per-language ``fetch/*.ql`` SELECT queries (US-002 Go / US-003 Rust) that
enumerate real AST nodes with their AUTHORITATIVE identity, decodes the BQRS to
JSON, maps rows to :class:`EnumItem`, applies vendor/generated exclusion, and
writes an exclusion log. This is GREENFIELD: ``codeql_runner`` previously emitted
only SARIF; this module adds the BQRS-decode path the IRIS enumerate-then-classify
extractor consumes.

The decoded rows feed the LLM classifier (US-005); the LLM never proposes names
or locations — it labels a subset of these real enumerated nodes.

Command used: ``codeql query run --database=<db> --output=<bqrs> <ql>`` then
``codeql bqrs decode --format=json <bqrs>``. (``database interpret-results`` is the
fallback if a CodeQL build rejects plain ``query run`` for these queries.)
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

import yaml

from tee_audit.trustir.codeql_runner import PACK_ROOT
from tee_audit.trustir.enumeration import EnumItem, matches_exclusion

logger = logging.getLogger(__name__)

# Per-query column orders for Go (ELEMENT FIRST, then scalar columns emitted by
# the Go fetch .ql — verified US-002). The element column is skipped; scalars are
# positional. Rust fetch .ql (US-003) instead emit a SINGLE pipe-delimited blob
# string as the 2nd column (e.g. "call_site|callee=<n>|arg_count=<n>|file=..|line=.."),
# so Rust rows are parsed by _parse_rust_blob, not positionally.
_GO_COLUMNS = {
    "fetch_calls": ["_", "name", "pkg", "type_name", "arg_count", "signature", "file", "line"],
    "fetch_functions": ["_", "name", "pkg", "type_name", "param_count", "signature", "file", "line"],
    "fetch_params": ["_", "param_name", "func_name", "pkg", "type_name", "param_type", "param_index", "file", "line"],
    "fetch_field_reads": ["_", "field_name", "base_type", "func_name", "pkg", "file", "line"],
}
# Rust fetch query names (each emits [entity, "<kind>|key=value|..."]).
_RUST_QUERIES = {"fetch_calls", "fetch_functions", "fetch_params", "fetch_field_reads"}
# JavaScript fetch query names. JS mirrors the Go positional-column format
# (one row marker "_" + scalars) so it reuses the Go column schema and the
# positional parse path in rows_to_items. JS emits "" for pkg/type_name where
# Go would carry a receiver type / package import path; the resolver grounds
# JS identity separately.
_JS_QUERIES = {"fetch_calls", "fetch_functions", "fetch_params", "fetch_field_reads"}


def _columns(language: str) -> dict[str, list[str]]:
    # Go and JavaScript share the positional-column schema.
    if language in ("go", "javascript"):
        return _GO_COLUMNS
    return {}  # rust uses the blob path


def _parse_rust_blob(query_name: str, blob: str) -> EnumItem | None:
    """Parse a Rust fetch pipe-delimited blob into an EnumItem (Decision-R).

    Blob shapes (US-003): ``<kind>|key=value|key=value|...``. The disambiguator
    stored in ``signature`` is arity (calls/functions) or the enclosing fn
    (params/field_reads) — the best precision rust-all 0.2.4 offers without a
    qualification API.
    """
    parts = (blob or "").split("|")
    kv: dict[str, str] = {}
    for p in parts[1:]:  # parts[0] is the kind label
        if "=" in p:
            k, _, v = p.partition("=")
            kv[k.strip()] = v.strip()
    kind = {"fetch_calls": "call", "fetch_functions": "function",
            "fetch_params": "param", "fetch_field_reads": "field_read"}[query_name]
    name = kv.get("callee") or kv.get("name") or kv.get("field")
    if not name:
        return None
    try:
        line = int(kv.get("line", "0"))
    except ValueError:
        line = 0
    arg_count = None
    sig = ""
    sig_text: str | None = None
    if query_name == "fetch_calls":
        try:
            arg_count = int(kv.get("arg_count", "")) if kv.get("arg_count") else None
        except ValueError:
            arg_count = None
        sig = str(arg_count) if arg_count is not None else ""
    elif query_name == "fetch_functions":
        sig = kv.get("param_count", "")          # arity = reliable resolver match key
        sig_text = kv.get("sig") or None          # real param-type signature (inspection)
    else:  # params / field_reads -> enclosing fn is the disambiguator
        sig = kv.get("enclosing_fn", "")
    return EnumItem(
        kind=kind, name=name, file=kv.get("file", ""), line=line,
        declaring_type_pkg=None, declaring_type_type=None,
        signature=sig, arg_count=arg_count, signature_text=sig_text,
        extra={k: v for k, v in kv.items()
               if k not in ("callee", "name", "field", "file", "line", "sig")},
    )


def _deny_globs() -> list[str]:
    """Load vendor/generated deny-globs from the bundled exclusion.yml."""
    from tee_audit.trustir.spec import bundled_spec_dir

    doc = yaml.safe_load((bundled_spec_dir() / "exclusion.yml").read_text(encoding="utf-8"))
    return list((doc or {}).get("deny_globs") or [])


def _scalar(val: Any) -> Any:
    """Coerce a BQRS JSON cell to a plain scalar.

    BQRS tuples may carry bare scalars (``"foo"``, ``3``) or wrapped dicts
    (``{"str": "foo"}``, ``{"i": 3}``, or entity dicts). Strings/ints are pulled
    out; entity dicts (no scalar key) become None (the element column is skipped
    anyway).
    """
    if isinstance(val, dict):
        for k in ("str", "s"):
            if k in val:
                return val[k]
        for k in ("i", "int", "n"):
            if k in val:
                try:
                    return int(val[k])
                except (TypeError, ValueError):
                    return val[k]
        return None  # entity column — not a scalar
    return val


def _find_tuples(doc: Any) -> tuple[list, list] | None:
    """Locate (columns_meta, tuples) anywhere in the bqrs-decode JSON.

    Returns the first dict that has a ``tuples`` list. Column metadata is best-
    effort; positional mapping is authoritative (see _COLUMNS).
    """
    if isinstance(doc, dict):
        if isinstance(doc.get("tuples"), list):
            return doc.get("columns") or [], doc["tuples"]
        for v in doc.values():
            found = _find_tuples(v)
            if found:
                return found
    elif isinstance(doc, list):
        for v in doc:
            found = _find_tuples(v)
            if found:
                return found
    return None


def rows_to_items(
    query_name: str, language: str, tuples: list[list[Any]]
) -> list[EnumItem]:
    """Map BQRS tuples for `query_name` to EnumItem rows.

    Go: positional columns (see _GO_COLUMNS). Rust: each tuple is
    ``[entity, "<kind>|key=value|..."]`` — parse via _parse_rust_blob.
    """
    if language == "rust":
        items: list[EnumItem] = []
        for tup in tuples:
            if not isinstance(tup, list) or len(tup) < 2:
                continue
            blob = _scalar(tup[1])
            if not isinstance(blob, str):
                continue
            it = _parse_rust_blob(query_name, blob)
            if it is not None:
                items.append(it)
        return items

    cols = _columns(language).get(query_name)
    if not cols:
        return []
    idx = {name: i for i, name in enumerate(cols)}
    kind = {"fetch_calls": "call", "fetch_functions": "function",
            "fetch_params": "param", "fetch_field_reads": "field_read"}[query_name]
    items = []
    for tup in tuples:
        if not isinstance(tup, list) or len(tup) < len(cols):
            continue

        def col(name: str) -> Any:
            i = idx.get(name)
            return _scalar(tup[i]) if i is not None and i < len(tup) else None

        name = col("name") or col("param_name") or col("field_name")
        if not name:
            continue
        try:
            line = int(col("line")) if col("line") is not None else 0
        except (TypeError, ValueError):
            line = 0
        arg_count = col("arg_count")
        try:
            arg_count = int(arg_count) if arg_count is not None else None
        except (TypeError, ValueError):
            arg_count = None
        extra = {k: col(k) for k in cols if k not in ("_", "name", "file", "line") and col(k) is not None}
        item = EnumItem(
            kind=kind,
            name=str(name),
            file=str(col("file") or ""),
            line=line,
            declaring_type_pkg=col("pkg"),
            declaring_type_type=(col("type_name") or col("base_type")),
            signature=col("signature") or col("param_type"),
            arg_count=arg_count,
            extra={k: str(v) for k, v in extra.items()},
        )
        items.append(item)
    return items


def run_fetch_queries(
    db_path: Path,
    language: str,
    codeql_path: Path,
    workdir: Path,
) -> list[EnumItem]:
    """Run all fetch .ql for `language` against `db_path`; return EnumItem rows.

    Writes an exclusion log (counts + sampled excluded paths) to
    ``<workdir>/fetch_exclusion.log``. Vendor/generated rows are dropped here as a
    secondary safety net (the fetch .ql already exclude via Fetch.qll).
    """
    db_path = Path(db_path).resolve()
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    fetch_dir = (PACK_ROOT / language / "fetch").resolve()
    globs = _deny_globs()

    codeql = str(codeql_path)
    all_items: list[EnumItem] = []
    excluded: list[str] = []
    per_query_counts: dict[str, dict[str, int]] = {}
    query_names = list(_RUST_QUERIES) if language == "rust" else list(_GO_COLUMNS.keys())  # go + javascript share _GO_COLUMNS
    for qname in query_names:
        ql = fetch_dir / f"{qname}.ql"
        if not ql.exists():
            logger.warning("fetch query missing: %s", ql)
            per_query_counts[qname] = {"kept": 0, "excluded": 0, "missing": 1}
            continue
        bqrs = workdir / f"{qname}.bqrs"
        # Produce a BQRS result file, then decode to JSON.
        proc = subprocess.run(
            [codeql, "query", "run", f"--database={db_path}", f"--output={bqrs}", str(ql)],
            capture_output=True, text=True,
        )
        raw_json = None
        if proc.returncode == 0 and bqrs.exists():
            dec = subprocess.run(
                [codeql, "bqrs", "decode", "--format=json", str(bqrs)],
                capture_output=True, text=True,
            )
            if dec.returncode == 0:
                try:
                    raw_json = json.loads(dec.stdout)
                except json.JSONDecodeError:
                    raw_json = None
        if raw_json is None:
            logger.warning("fetch decode failed for %s: %s", qname, (proc.stderr or dec.stderr)[-300:])  # type: ignore[name-defined]
            per_query_counts[qname] = {"kept": 0, "excluded": 0, "error": 1}
            continue

        found = _find_tuples(raw_json)
        tuples = found[1] if found else []
        items = rows_to_items(qname, language, tuples)
        kept = [it for it in items if not matches_exclusion(it.file, globs)]
        excl = [it.file for it in items if matches_exclusion(it.file, globs)]
        all_items.extend(kept)
        excluded.extend(excl[:5])  # sample
        per_query_counts[qname] = {"kept": len(kept), "excluded": len(excl)}

    log_path = workdir / "fetch_exclusion.log"
    lines = [f"# fetch exclusion log (language={language}, deny_globs={len(globs)})"]
    for q, c in per_query_counts.items():
        lines.append(f"{q}: {c}")
    if excluded:
        lines.append("sample excluded paths:")
        lines.extend(f"  {p}" for p in excluded)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return all_items


__all__ = ["run_fetch_queries", "rows_to_items", "PACK_ROOT"]
