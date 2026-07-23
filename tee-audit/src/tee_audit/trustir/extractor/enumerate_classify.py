"""Iteration-3 IRIS extractor: enumerate (CodeQL) then classify (LLM).

Replaces the iteration-2 two-pass zone extractor (zone_map + zone_extract).
CodeQL's ``run_fetch_queries`` enumerates real AST nodes with AUTHORITATIVE
identity; the LLM then CLASSIFIES a subset into role-tagged annotations. The
LLM never proposes file/line/id — those are inherited from CodeQL by the
resolver. Status is never emitted; the solver owns it post-CodeQL.

Public entry points:

- :func:`classify_repo` — run fetch + LLM classification, return
  ``(TrustAnnotationSet, EnumItemIndex)``.
- :func:`extract_repo` — thin wrapper returning ``(ann_set, {})`` to satisfy the
  legacy two-tuple call site in :mod:`pipeline` (zone_map is retired; the
  second slot is kept only as an empty dict for backward compatibility and is
  not consumed downstream).
"""

from __future__ import annotations

import functools
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml

from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt
from tee_audit.trustir.annotations import (
    AnnotationKind,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.codeql_fetch import run_fetch_queries
from tee_audit.trustir.enumeration import EnumItem, EnumItemIndex
from tee_audit.trustir.spec import bundled_spec_dir

logger = logging.getLogger(__name__)

# Batch caps — keep each LLM call inside the prompt-loader's enumeration var
# limit (prompt_loader._LONG_LIMIT = 24000 chars for `enumeration`). 20000 leaves
# headroom so no batch is truncated and the LLM sees every row in its batch.
_MAX_ROWS_PER_BATCH = 200
_MAX_TOKEN_BUDGET_CHARS = 20_000

# Sentinel "name" values the Rust fetch emits for bindings that carry NO real
# identifier (tuple/wildcard/struct patterns like `_`, `(a, b)`, `..`; or a field
# read with no enclosing callable -> "<none>"). These are not meaningful API
# names, so they are dropped before the LLM sees them and again if the LLM
# echoes one back — they must never become facts. (Decision-R precision fix:
# rust-all 0.2.4 has no clean qualification API, so the fetch over-includes
# anonymous bindings.)
_NON_NAME_MARKERS = frozenset({"<non-ident-pat>", "<none>"})


def _is_marker_name(name: str | None) -> bool:
    """True when ``name`` is absent or a fetch-emitted anonymity marker."""
    return not name or name.strip() in _NON_NAME_MARKERS


# Macro-expanded identifier prefixes (PyO3 ``#[pyfunction]``/``#[pymethods]``,
# clap derives). rust-all enumerates the EXPANDED symbols — e.g.
# ``__pyfunction_parse_quote``, ``__pymethod_to_json__``, ``__clap_arg_matches``
# — plus their generated params (``_slf``/``_args``/``_kwargs``). These are FFI
# shims wrapping the real logic; labeling them as trust sources/sinks (notably
# ``_slf``/``self`` as a sink) is pure noise that also defeats Rust taint
# tracking through the macro-expanded binding layer. Dropping them is the
# name-level analog of excluding vendored/generated paths (exclusion.yml): the
# LLM never sees generated identifiers, so it labels the real verifier logic.
# Generalizable to any PyO3/clap Rust project — not repo-specific.
_GENERATED_PREFIXES = (
    # PyO3 (#[pyfunction]/#[pymethods]) + its module-init internals.
    "__pyfunction_", "__pymethod_", "__pyclass_", "__pymodule_", "__pyo3_",
    # clap derives.
    "__clap_",
    # wasm-bindgen.
    "__wasm_bindgen_",
    # serde #[derive(Deserialize/Serialize)] — rust-all enumerates the expanded
    # __deserialize/__serialize helpers and their visitor locals (__value/__seq/
    # __map caught via the enclosing-fn signature in _is_generated_signature).
    "__deserialize", "__serialize",
    # parity SCALE-codec #[derive(Encode/Decode)] — __codec_input_edqy etc.
    "__codec_",
    # derive_more / pin-project private field helpers.
    "__derive_more", "__priv_",
)
# Param names PyO3 synthesizes for *args/**kwargs/self. A param row's
# ``signature`` holds its ENCLOSING function's name, so a generated enclosing fn
# is caught by _is_generated_signature below; these cover the bare-param case.
_GENERATED_PARAM_NAMES = frozenset({"_slf", "_self", "self"})


def _is_generated_name(name: str | None) -> bool:
    """True when ``name`` is a macro-expanded identifier (PyO3/clap) or a
    synthesized self-param."""
    n = (name or "").strip()
    return any(n.startswith(p) for p in _GENERATED_PREFIXES) or n in _GENERATED_PARAM_NAMES


def _is_generated_signature(signature: str | None) -> bool:
    """True when ``signature`` is a macro-expanded enclosing-function name.

    For Rust PARAM rows ``signature`` is the enclosing function's name (used as
    the resolver disambiguator), so a param of ``__pyfunction_py_verify`` carries
    ``signature="__pyfunction_py_verify"`` — this catches the generated-fn params
    that _is_generated_name (which sees only the param name ``_args``) would miss.
    Function/call rows use arity (e.g. "4") here, which never matches.
    """
    s = (signature or "").strip()
    return any(s.startswith(p) for p in _GENERATED_PREFIXES)


def _is_droppable(name: str | None, signature: str | None = None) -> bool:
    """True when an item should never reach the LLM: anonymity marker OR a
    macro-expanded identifier (by name or enclosing-fn signature)."""
    return (
        _is_marker_name(name)
        or _is_generated_name(name)
        or _is_generated_signature(signature)
    )


# Layer A: FFI / language-binding wrappers and module-wiring functions are NOT
# trust-decision authorities — they only DELEGATE to the verifier core. The LLM
# sometimes labels them as authorities (e.g. ``js_verify``, ``py_verify``,
# ``register_module``); dropping that label forces the real verdict function
# (e.g. ``verify_impl``), where the appraisal guards live, to be the authority
# so intra-proc dominance applies. Name-based heuristic (conservative);
# attribute-based detection (#[wasm_bindgen]/#[pymodule]/extern "C") is the
# principled follow-up.
_FFI_WIRING_AUTHORITY_RE = re.compile(r"^(js_|py_|wasm_)|_cb$|^register_module$")


def _is_ffi_or_wiring_authority(name: str | None) -> bool:
    """True when ``name`` is an FFI binding entry or module-wiring function
    (wasm/PyO3/extern callback / module registration) — not a trust verdict."""
    return bool(_FFI_WIRING_AUTHORITY_RE.match((name or "").strip()))


def _norm_relpath(p: str | None) -> str:
    """Normalize a repo-relative path for prefix matching: strip a leading
    ``./``, collapse backslashes, drop a single leading slash."""
    s = (p or "").strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/")


def path_in_scope(file_path: str | None, scope: list[str] | None) -> bool:
    """True when ``file_path`` is within one of the in-scope ``scope`` prefixes.

    ``scope`` is a list of repo-relative path prefixes (e.g. ``["suave/"]``).
    Empty/None scope means the whole repo is in scope (backward compatible).
    Used to restrict enumeration to a fork's own enclave/trust layer (e.g.
    suave-geth = go-ethereum + SUAVE → scope ``suave/``) so inherited code is
    not mislabeled as TEE trust logic. Matching is on normalized path prefixes.
    """
    if not scope:
        return True
    f = _norm_relpath(file_path)
    return any(f.startswith(_norm_relpath(p)) for p in scope)


# --------------------------------------------------------------------------- #
# Catalog (enum_registry.yml) — authoritative role/kind tables
# --------------------------------------------------------------------------- #


@functools.lru_cache(maxsize=1)
def _registry() -> dict[str, list[str]]:
    """Load enum_registry.yml as ``{category: [value, ...]}``."""
    doc = yaml.safe_load(
        (bundled_spec_dir() / "enum_registry.yml").read_text(encoding="utf-8")
    )
    return {k: list(v or []) for k, v in (doc or {}).items()}


# role string -> AnnotationKind. The role-catalog gate (below) drops any role
# not present in this map before the annotation reaches the resolver.
def _role_to_kind_map() -> dict[str, AnnotationKind]:
    reg = _registry()
    mapping: dict[str, AnnotationKind] = {}
    for role in reg.get("claim_field_role", []):
        mapping[role] = AnnotationKind.VERIFIER
    for role in reg.get("authority_kind", []):
        mapping[role] = AnnotationKind.AUTHORITY
    for role in reg.get("guard_kind", []):
        mapping[role] = AnnotationKind.GUARD
    for role in reg.get("taint_propagator_role", []):
        mapping[role] = AnnotationKind.PROPAGATOR
    for role in reg.get("trust_source_role", []):
        mapping[role] = AnnotationKind.SOURCE
    for role in reg.get("observable_sink_role", []):
        mapping[role] = AnnotationKind.SINK
    for role in reg.get("trust_sink_role", []):
        mapping[role] = AnnotationKind.SINK
    return mapping


def _catalog_roles() -> frozenset[str]:
    """All role values the LLM is permitted to emit (parser-level gate)."""
    return frozenset(_role_to_kind_map().keys())


# --------------------------------------------------------------------------- #
# EnumItem -> LLM enumeration row rendering
# --------------------------------------------------------------------------- #


def _render_item(idx: int, it: EnumItem) -> str:
    """Render one EnumItem as a compact TSV-ish row for the prompt."""
    parts = [
        f"[{idx}] kind={it.kind}",
        f"name={it.name}",
        f"declaring_type_pkg={it.declaring_type_pkg or ''}",
        f"declaring_type_type={it.declaring_type_type or ''}",
    ]
    if it.signature:
        parts.append(f"signature={it.signature}")
    if it.arg_count is not None:
        parts.append(f"arg_count={it.arg_count}")
    return " ".join(parts)


def _render_batch(items: list[EnumItem]) -> str:
    return "\n".join(_render_item(i, it) for i, it in enumerate(items))


# --------------------------------------------------------------------------- #
# Batching
# --------------------------------------------------------------------------- #


def _make_batches(items: list[EnumItem]) -> list[list[EnumItem]]:
    """Group items into LLM-sized batches.

    Two constraints: ``_MAX_ROWS_PER_BATCH`` rows, and an ~8k-token budget
    estimated from the rendered text length. Group by ``declaring_type`` first
    (keeps a callee's overloads/params together for the LLM).
    """
    if not items:
        return []

    # Stable group by declaring_type (None -> "").
    ordered: list[EnumItem] = sorted(
        items, key=lambda it: (it.declaring_type or "", it.name, it.kind)
    )

    batches: list[list[EnumItem]] = []
    current: list[EnumItem] = []
    current_chars = 0
    for it in ordered:
        row_chars = len(_render_item(len(current), it)) + 1
        if current and (
            len(current) >= _MAX_ROWS_PER_BATCH
            or current_chars + row_chars > _MAX_TOKEN_BUDGET_CHARS
        ):
            batches.append(current)
            current = []
            current_chars = 0
        current.append(it)
        current_chars += row_chars
    if current:
        batches.append(current)
    return batches


# --------------------------------------------------------------------------- #
# LLM call + JSON parse
# --------------------------------------------------------------------------- #


def _parse_json_array(text: str) -> list[dict[str, Any]]:
    """Best-effort parse of an LLM response into a list of dicts.

    Strips markdown code fences if present and tolerates surrounding prose by
    extracting the outermost ``[ ... ]`` block.
    """
    s = (text or "").strip()
    if s.startswith("```"):
        # drop the opening fence line
        s = s.split("\n", 1)[-1] if "\n" in s else s
        if s.endswith("```"):
            s = s.rsplit("```", 1)[0]
        s = s.strip()
    if not s:
        return []
    try:
        data = json.loads(s)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            # tolerate {"annotations": [...]} envelope
            inner = data.get("annotations") or data.get("items")
            if isinstance(inner, list):
                return [d for d in inner if isinstance(d, dict)]
        return []
    except json.JSONDecodeError:
        # Fall back: carve out the outermost bracketed block.
        match = re.search(r"\[.*\]", s, flags=re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                return [d for d in data if isinstance(d, dict)]
            except json.JSONDecodeError:
                return []
        return []


def _classify_batch(
    client: LLMClient,
    items: list[EnumItem],
    *,
    language: str,
    twe_family: str,
    repo_summary: str,
) -> list[dict[str, Any]]:
    """One LLM call over one batch; return parsed list-of-dict (no validation)."""
    enumeration = _render_batch(items)
    system = (
        "You are the classification layer of the TrustIR iteration-3 IRIS "
        "pipeline. CodeQL enumerated real API nodes; you label a SUBSET with a "
        "catalog role. NEVER emit file/line/id/status. Respond with ONLY a "
        "JSON array."
    )
    user = load_prompt(
        "trustir_classify",
        enumeration=enumeration,
        twe_family=twe_family,
        language=language,
        repo_summary=repo_summary,
    )
    raw = client.complete(system, user, temperature=0)
    return _parse_json_array(raw)


def _parse_json_object(text: str) -> dict[str, Any]:
    """Best-effort parse of an LLM response into a ``str->str`` dict (the
    guard->authority linking map). Mirrors ``_parse_json_array``'s fence/prose
    tolerance, but carves the outermost ``{ ... }`` block."""
    s = (text or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[-1] if "\n" in s else s
        if s.endswith("```"):
            s = s.rsplit("```", 1)[0]
        s = s.strip()
    if not s:
        return {}
    try:
        data = json.loads(s)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v}
        return {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", s, flags=re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items() if v}
            except json.JSONDecodeError:
                return {}
        return {}


def link_guards_to_authorities(
    client: LLMClient,
    ann_set: TrustAnnotationSet,
    *,
    language: str,
    repo_summary: str,
    twe_family: str,
) -> TrustAnnotationSet:
    """Second-pass: link each GUARD to the AUTHORITY it dominates.

    The per-batch classify prompt can only link a guard to an authority when
    both land in the same batch; with many batches most guards never see their
    authority and end up with no ``dominates`` — an inert guard (no
    ``hasSuppressor`` barrier, so it cannot model protection). On dcap-qvl this
    left 83 of 99 resolved guards inert. This single LLM call sees ALL guards +
    ALL authorities at once and sets ``dominates`` from the authority set,
    decoupling the link from batching.

    Semantic only: the LLM picks the authority NAME (informed by names + roles);
    the resolver still verifies the names exist. A pick not in the authority set
    is dropped (no hallucinated authorities). Guards that already carry
    ``dominates`` (set correctly in-batch) are left untouched. No-ops when there
    are no authorities or no guards lacking ``dominates``.
    """
    authorities = [a for a in ann_set.annotations if a.kind is AnnotationKind.AUTHORITY]
    guards = [a for a in ann_set.annotations
              if a.kind is AnnotationKind.GUARD and not a.dominates]
    if not authorities or not guards:
        return ann_set

    auth_names = sorted({a.name for a in authorities if a.name})
    guard_lines = [f"- {a.name} ({a.role})" for a in guards if a.name]
    system = (
        "You link TEE verification GUARD functions to the AUTHORITY function "
        "whose acceptance each guard protects (the guard must succeed before the "
        "authority grants trust). Pick each guard's authority FROM THE LIST. "
        "Respond with ONLY a JSON object {\"<guard_name>\": \"<authority_name>\"}. "
        "Use the exact authority name; omit a guard entirely if no listed "
        "authority fits."
    )
    user = (
        f"Repo: {repo_summary}\n\n"
        f"AUTHORITIES (pick dominates from these ONLY):\n"
        + "".join(f"- {n}\n" for n in auth_names)
        + "\nGUARDS (assign each the authority it must succeed-before):\n"
        + "".join(f"{ln}\n" for ln in guard_lines)
        + "\nRespond ONLY with the JSON object."
    )
    raw = client.complete(system, user, temperature=0)
    mapping = _parse_json_object(raw)

    valid = set(auth_names)
    updated = 0
    for a in guards:
        pick = mapping.get(a.name)
        if pick and pick in valid:
            a.dominates = pick
            updated += 1
    logger.info(
        "link_guards_to_authorities: set dominates on %d/%d guards (authorities=%d)",
        updated, len(guards), len(auth_names),
    )
    return ann_set


# --------------------------------------------------------------------------- #
# LLM dict -> TrustAnnotation (catalog gate + id assignment + no file/line)
# --------------------------------------------------------------------------- #


def _slug(name: str) -> str:
    """ASCII slug usable inside an annotation id."""
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(name or "")).strip("-").lower()
    return s or "anon"


def _build_annotation(
    item: dict[str, Any],
    role_to_kind: dict[str, AnnotationKind],
    *,
    counter: dict[str, int],
) -> TrustAnnotation | None:
    """Build one TrustAnnotation from an LLM dict, applying the catalog gate.

    Returns None if the role is absent or not in the catalog (the gate drop
    case); the caller logs the drop. NEVER copies file/line/id from the LLM —
    location is owned by CodeQL and inherited by the resolver; id is assigned
    deterministically here.
    """
    # Principle hardening: the LLM must NEVER set file/line/id/status. This
    # function never reads those keys anyway; this defensive check makes the
    # invariant STRUCTURAL — a future prompt/schema regression that leaks them is
    # logged loudly instead of passing silently. (Architect rec #2.)
    _forbidden = {"file", "line", "id", "status", "severity", "verdict"}
    leaked = [k for k in _forbidden if k in item]
    if leaked:
        logger.warning("classify_repo: LLM leaked forbidden keys %r for name=%r (stripped, ignored)",
                       leaked, item.get("name"))

    name = str(item.get("name") or "").strip()
    role = str(item.get("role") or "").strip()
    if _is_marker_name(name) or not role:
        return None
    # Echo gate: generated symbols are dropped pre-LLM, but if the LLM echoes a
    # PyO3/clap identifier (by name or enclosing-fn signature) it must never
    # become a fact. (Defensive — mirrors the anonymity-marker hardening.)
    if _is_generated_name(name) or _is_generated_signature(str(item.get("signature") or "")):
        logger.info(
            "classify_repo: dropping generated-symbol echo name=%r sig=%r",
            name, item.get("signature"),
        )
        return None
    kind = role_to_kind.get(role)
    if kind is None:
        logger.info("classify_repo: catalog-gate dropping role=%r name=%r", role, name)
        return None
    # Layer A: an authority must be a trust VERDICT function, not an FFI/wiring
    # wrapper. Drop the label so the verifier core becomes the authority.
    if kind is AnnotationKind.AUTHORITY and _is_ffi_or_wiring_authority(name):
        logger.info(
            "classify_repo: dropping FFI/wiring authority name=%r (not a verdict fn)",
            name,
        )
        return None

    counter[kind.value] = counter.get(kind.value, 0) + 1
    aid = f"{kind.value}-{_slug(name)}-{counter[kind.value]}"

    sink_args_raw = item.get("sink_args")
    sink_args: list[str] | None = None
    if isinstance(sink_args_raw, list) and sink_args_raw:
        sink_args = [str(x) for x in sink_args_raw if x is not None and str(x) != ""]

    ann = TrustAnnotation(
        id=aid,
        kind=kind,
        role=role,
        name=name,
        declaring_type_pkg=(str(item.get("declaring_type_pkg") or "") or None),
        declaring_type_type=(str(item.get("declaring_type_type") or "") or None),
        signature=(str(item.get("signature") or "") or None),
        sink_args=sink_args,
    )
    # Kind-specific optional fields (copied verbatim from the LLM dict; never
    # file/line/id/status).
    if kind is AnnotationKind.AUTHORITY:
        subject_param = item.get("subject_param")
        if isinstance(subject_param, str) and subject_param:
            ann.subject_param = subject_param
        subject_role = item.get("subject_role")
        if isinstance(subject_role, str) and subject_role:
            ann.subject_role = subject_role
        protected = item.get("protected_asset")
        if isinstance(protected, str) and protected:
            ann.protected_asset = protected
        claim_field_role = item.get("claim_field_role")
        if isinstance(claim_field_role, str) and claim_field_role:
            ann.claim_field_role = claim_field_role
    elif kind is AnnotationKind.VERIFIER:
        claim_field_role = item.get("claim_field_role")
        if isinstance(claim_field_role, str) and claim_field_role:
            ann.claim_field_role = claim_field_role
        accessor = item.get("accessor")
        if isinstance(accessor, str) and accessor:
            ann.accessor = accessor
    elif kind is AnnotationKind.GUARD:
        dominates = item.get("dominates")
        if isinstance(dominates, str) and dominates:
            ann.dominates = dominates
    elif kind is AnnotationKind.SOURCE:
        param = item.get("param") or item.get("subject_param")
        if isinstance(param, str) and param:
            ann.param = param
    return ann


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def classify_repo(
    repo_path: Path | str,
    language: str,
    codeql_path: Path | str,
    workdir: Path | str,
    client: LLMClient,
    repo_summary: str = "",
    twe_family: str = "all",
    db_path: Path | str | None = None,
    persist_dir: Path | str | None = None,
    max_workers: int = 1,
    scope: list[str] | None = None,
) -> tuple[TrustAnnotationSet, EnumItemIndex]:
    """Enumerate (CodeQL) + classify (LLM) a whole repo.

    Steps:
      1. ``run_fetch_queries`` -> ``EnumItem`` rows (US-004), then drop bindings
         with no real identifier (``<non-ident-pat>``/``<none>``).
      2. Batch into <=200-row / ~8k-token groups.
      3. One LLM call per batch (``trustir_classify`` prompt).
      4. Parser-level CATALOG GATE: drop any annotation whose role is not in
         ``enum_registry.yml`` BEFORE returning.
      5. Build a :class:`TrustAnnotation` per surviving item: infer ``kind`` from
         the role category; assign ``id = f"{kind}-{slug(name)}-{n}"``. NEVER
         copy file/line from the LLM (CodeQL owns it; the resolver inherits).
      6. Dedup exact-duplicate annotations (same kind+role+name+identity).

    Returns ``(TrustAnnotationSet, EnumItemIndex)`` — the index is consumed by
    the resolver to ground each annotation against CodeQL's authoritative
    location.

    ``db_path`` is optional; when omitted, a CodeQL DB is built/cached via
    :func:`tee_audit.trustir.codeql_runner.build_or_get_db`. ``persist_dir``,
    when given, writes ``enum_items.json`` (the exact CodeQL enumeration the LLM
    saw) and ``annotations.raw.json`` (the LLM's classifications BEFORE resolve),
    so the raw extraction is inspectable alongside the resolver's grounded set.
    """
    root = Path(repo_path).resolve()
    work = Path(workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)

    # 1. Enumerate.
    if db_path is None:
        from tee_audit.trustir.codeql_runner import build_or_get_db

        db_path, _ = build_or_get_db(root, language, Path(codeql_path), work.parent)
    items = run_fetch_queries(Path(db_path), language, Path(codeql_path), work)
    # Optional subsystem scoping: for a repo that is a fork (e.g. suave-geth =
    # go-ethereum + SUAVE), restrict enumeration to the project's own enclave/
    # trust layer so inherited code is not mislabeled as TEE trust logic. Default
    # None = whole repo (backward compatible).
    if scope:
        before = len(items)
        items = [it for it in items if path_in_scope(it.file, scope)]
        logger.info(
            "classify_repo: scope=%s kept %d/%d enumerated items for %s",
            scope, len(items), before, root.name,
        )
    # Drop anonymity markers AND macro-expanded PyO3/clap identifiers (by name
    # or enclosing-fn signature) so the LLM labels real verifier logic, not FFI
    # binding shims. See _is_droppable for the rationale.
    enumerable = [it for it in items if not _is_droppable(it.name, it.signature)]
    dropped = len(items) - len(enumerable)
    if dropped:
        marker_dropped = sum(1 for it in items if _is_marker_name(it.name))
        logger.info(
            "classify_repo: dropped %d items before classification "
            "(%d macro-generated PyO3/clap, %d anonymity-marker)",
            dropped, dropped - marker_dropped, marker_dropped,
        )
    index = EnumItemIndex(enumerable, language)
    logger.info(
        "classify_repo: %d enumerated items (%d unique keys) for %s",
        len(items), len(index), root.name,
    )

    # 2. Batch.
    batches = _make_batches(enumerable)

    # 3-4. Classify + catalog gate.
    role_to_kind = _role_to_kind_map()
    counter: dict[str, int] = {}
    annotations: list[TrustAnnotation] = []
    n_batches = len(batches)
    logger.info(
        "classify_repo: classifying %d batches (max_workers=%d) for %s",
        n_batches, max_workers, root.name,
    )

    def _do_batch(idx: int, batch: list[EnumItem]) -> list[dict[str, Any]]:
        t0 = time.monotonic()
        try:
            items = _classify_batch(
                client, batch,
                language=language, twe_family=twe_family, repo_summary=repo_summary,
            )
            logger.info(
                "classify_repo: batch %d/%d -> %d raw items in %.1fs",
                idx, n_batches, len(items), time.monotonic() - t0,
            )
            return items
        except Exception:  # noqa: BLE001 — one bad batch must not kill the run
            logger.exception(
                "classify_repo: batch %d/%d failed (%d items) in %.1fs",
                idx, n_batches, len(batch), time.monotonic() - t0,
            )
            return []

    # Each LLM call is pure network I/O (glm-5.2 is a ~23s/call reasoning model,
    # 0 local CPU), so concurrent batches are nearly free up to the API rate
    # limit. Results are collected in submission (index) order, so annotation id
    # assignment stays deterministic regardless of completion order.
    if max_workers and max_workers > 1 and n_batches > 1:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            batch_results = list(
                pool.map(_do_batch, range(1, n_batches + 1), batches)
            )
    else:
        batch_results = [_do_batch(i, b) for i, b in enumerate(batches, 1)]

    raw_total = 0
    for items in batch_results:
        raw_total += len(items)
        for raw in items:
            ann = _build_annotation(raw, role_to_kind, counter=counter)
            if ann is not None:
                annotations.append(ann)
    logger.info(
        "classify_repo: %d raw LLM items -> %d post-catalog-gate annotations",
        raw_total, len(annotations),
    )

    # Dedup exact-duplicate annotations (same kind+role+name+identity+sink_args).
    # Rust keys on (name, signature); the LLM often re-labels a common-named
    # call (a closure, a macro, "inner") under the same role, which would emit
    # identical fact clauses. Keep the first, drop the rest.
    seen: set[tuple] = set()
    unique: list[TrustAnnotation] = []
    for a in annotations:
        key = (
            a.kind.value, a.role, a.name,
            a.declaring_type_pkg, a.declaring_type_type,
            a.signature, tuple(a.sink_args or ()), a.param,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(a)
    if len(unique) != len(annotations):
        logger.info(
            "classify_repo: deduped %d duplicate annotations -> %d unique",
            len(annotations), len(unique),
        )
    annotations = unique

    ann_set = TrustAnnotationSet(
        repo=root.name,
        language=language,
        annotations=annotations,
    )

    # Second-pass guard->authority linking. The per-batch classify prompt can
    # only link a guard to an authority when both land in the same batch; with
    # many batches most guards miss their authority and end up without
    # `dominates` (inert — no hasSuppressor barrier). One global call sees ALL
    # guards + ALL authorities and fills `dominates` from the authority set,
    # decoupling the link from batching. No-ops when there are no authorities or
    # no guards lacking `dominates`.
    ann_set = link_guards_to_authorities(
        client, ann_set,
        language=language, repo_summary=repo_summary, twe_family=twe_family,
    )

    # Persist the pre-resolve artifacts so the LLM's raw role assignments (and
    # the exact CodeQL enumeration it saw) are inspectable alongside the resolved
    # set. The resolved set is written by the pipeline caller.
    if persist_dir is not None:
        pd = Path(persist_dir)
        pd.mkdir(parents=True, exist_ok=True)
        (pd / "enum_items.json").write_text(
            json.dumps([it.to_dict() for it in enumerable], indent=2),
            encoding="utf-8",
        )
        (pd / "annotations.raw.json").write_text(
            ann_set.model_dump_json(indent=2), encoding="utf-8",
        )

    return ann_set, index


def extract_repo(
    client: LLMClient,
    repo_path: Path | str,
    language: str = "go",
    results_dir: Path | str | None = None,
    codeql_path: Path | str | None = None,
    repo_summary: str = "",
    twe_family: str = "all",
    db_path: Path | str | None = None,
    **_legacy: Any,
) -> tuple[TrustAnnotationSet, dict[str, Any]]:
    """Backward-compatible wrapper for the legacy two-tuple call site.

    Runs :func:`classify_repo` and returns ``(ann_set, {})``. The empty dict
    replaces the retired zone_map; no downstream consumer reads it. Persists
    ``annotations.json`` to ``results_dir`` if given.
    """
    if codeql_path is None:
        from tee_audit.utils.codeql_check import find_codeql, validate_codeql

        f = find_codeql()
        if not f:
            msg = "extract_repo: codeql_path required (no CodeQL on PATH)"
            raise RuntimeError(msg)
        codeql_path = validate_codeql(Path(f))

    work = Path(results_dir) if results_dir is not None else Path(repo_path) / ".trustir-work"
    work.mkdir(parents=True, exist_ok=True)
    ann_set, _index = classify_repo(
        repo_path=repo_path,
        language=language,
        codeql_path=codeql_path,
        workdir=work,
        client=client,
        repo_summary=repo_summary,
        twe_family=twe_family,
        db_path=db_path,
    )

    if results_dir is not None:
        out = Path(results_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "annotations.json").write_text(
            json.dumps(ann_set.model_dump(mode="json"), indent=2), encoding="utf-8"
        )
    return ann_set, {}


__all__ = ["classify_repo", "extract_repo"]
