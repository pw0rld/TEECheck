"""Generate the CodeQL ``GeneratedTrustFacts.qll`` fact module from resolved TrustIR.

FACTS ONLY — no vulnerability logic. The generator reads the binder's
:class:`BindResult` (resolved IR + per-fact resolutions) and emits, for the
requested language, a ``module GeneratedTrustFacts`` whose predicates hold at
the resolved ``(file, line)`` locations. Unresolved/rejected facts are NEVER
emitted (zero-hallucination: only binder-verified locations appear).

The emitted clauses bind a ``DataFlow::Node n`` to a source location via
``n.asExpr().getLocation()``. The exact node-binding API is language-specific and
is validated at CodeQL pack-compile time (US-004/US-005); this generator's own
correctness is verified structurally (US-003 tests).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tee_audit.trustir.binder.resolver import BindResult, Resolution

# IR language -> CodeQL import + DataFlow node-accessor for location binding.
_LANG_IMPORT = {
    "go": "go",
    "golang": "go",
    "javascript": "javascript",
    "typescript": "javascript",
    "js": "javascript",
    "ts": "javascript",
    "rust": "rust",
    "rs": "rust",
}


def normalize_language(language: str) -> str:
    key = (language or "").strip().lower()
    if key not in _LANG_IMPORT:
        raise ValueError(f"unsupported language for CodeQL fact generation: {language!r}")
    return _LANG_IMPORT[key]


def _loc_from_dict(d: dict[str, Any]) -> tuple[str, int] | None:
    """Extract a (file, line) location from a flow/config/observable/suppressor dict."""
    sel = d.get("selector")
    if isinstance(sel, dict):
        f = sel.get("file")
        ln = sel.get("line")
        if f and ln:
            return str(f), int(ln)
    f = d.get("file")
    ln = d.get("line")
    if f and ln:
        return str(f), int(ln)
    return None


def _clause(param: str, role_value: str, file: str, line: int) -> str:
    """One fact clause: binds predicate params to a single resolved location."""
    return (
        "    (\n"
        f'      {param} = "{_ql_escape(role_value)}" and\n'
        f"      n.asExpr().getLocation().getFile().getRelativePath() = "
        f'"{_ql_escape(file)}" and\n'
        f"      n.asExpr().getLocation().getStartLine() = {int(line)}\n"
        "    )"
    )


def _ql_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _predicate(name: str, param_name: str, clauses: list[str]) -> str:
    body = " none()" if not clauses else "\n" + " or\n".join(clauses) + "\n"
    return (
        f"  predicate {name}(DataFlow::Node n, string {param_name}) {{{body}  }}\n"
    )


def _gather(
    result: BindResult,
) -> dict[str, list[tuple[str, str, int]]]:
    """Collect resolved (role, file, line) tuples grouped by predicate name."""
    out: dict[str, list[tuple[str, str, int]]] = {
        "isClaimField": [],
        "isAuthorityPoint": [],
        "isAuthoritySubject": [],
        "isTrustSource": [],
        "isTrustSink": [],
        "hasSuppressor": [],
    }
    ir = result.resolved
    res: dict[str, Resolution] = result.resolutions

    def _node_loc(r: Resolution) -> tuple[str, int] | None:
        if r.status != "resolved" or not r.node:
            return None
        node = r.node
        f = node.get("file")
        ln = node.get("line")
        if f and ln:
            return str(f), int(ln)
        return None

    for cf in getattr(ir, "claim_fields", []):
        loc = _node_loc(res.get(cf.id, _empty(cf.id)))
        if loc:
            out["isClaimField"].append((str(cf.role.value), *loc))

    for ap in getattr(ir, "authority_points", []):
        loc = _node_loc(res.get(ap.id, _empty(ap.id)))
        if loc:
            out["isAuthorityPoint"].append((str(ap.kind.value), *loc))
        sub_id = f"{ap.id}.authority_subject"
        sub_res = res.get(sub_id)
        sub_loc = _node_loc(sub_res) if sub_res else None
        if sub_loc and ap.authority_subject is not None:
            role = (
                ap.authority_subject.role.value
                if ap.authority_subject.role is not None
                else "subject"
            )
            out["isAuthoritySubject"].append((role, *sub_loc))

    # flow / config / observable / state dicts: emit from inline locations.
    for d in getattr(ir, "flow_sources", []):
        loc = _loc_from_dict(d)
        role = d.get("role") or d.get("kind") or "source"
        if loc:
            out["isTrustSource"].append((str(role), *loc))
    for d in getattr(ir, "config_sources", []):
        loc = _loc_from_dict(d)
        role = d.get("role") or d.get("weak_mode") or d.get("kind") or "config"
        if loc:
            out["isTrustSource"].append((str(role), *loc))
    for d in getattr(ir, "flow_sinks", []):
        loc = _loc_from_dict(d)
        role = d.get("role") or d.get("kind") or "sink"
        if loc:
            out["isTrustSink"].append((str(role), *loc))
    for d in getattr(ir, "observable_sinks", []):
        loc = _loc_from_dict(d)
        role = d.get("role") or d.get("kind") or "observable"
        if loc:
            out["isTrustSink"].append((str(role), *loc))
    for d in getattr(ir, "suppressors", []):
        loc = _loc_from_dict(d)
        kind = d.get("kind") or "suppress"
        if loc:
            out["hasSuppressor"].append((str(kind), *loc))

    return out


def _empty(fact_id: str) -> Resolution:
    return Resolution(fact_id=fact_id, status="unresolved", reason="not_examined")


_PRED_PARAM = {
    "isClaimField": "role",
    "isAuthorityPoint": "kind",
    "isAuthoritySubject": "role",
    "isTrustSource": "role",
    "isTrustSink": "role",
    "hasSuppressor": "suppressor",
}


def generate_facts(result: BindResult, language: str = "go") -> str:
    """Return the GeneratedTrustFacts.qll text for ``language`` from ``result``."""
    ql_import = normalize_language(language)
    grouped = _gather(result)

    clauses_by_pred = {
        pred: [_clause(_PRED_PARAM[pred], role, file, line) for role, file, line in items]
        for pred, items in grouped.items()
    }

    # isAdditionalTrustFlowStep / authoritySubjectOf stay none() (no location model yet).
    parts = [
        "/**\n",
        " * GeneratedTrustFacts.qll — GENERATED from resolved TrustIR. FACTS ONLY.\n",
        f" * Language: {ql_import}. Populate from binder-resolved (file, line) locations.\n",
        " */\n",
        f"import {ql_import}\n\n",
        "module GeneratedTrustFacts {\n",
    ]
    for pred in ("isClaimField", "isAuthorityPoint", "isAuthoritySubject",
                 "isTrustSource", "isTrustSink", "hasSuppressor"):
        parts.append(_predicate(pred, _PRED_PARAM[pred], clauses_by_pred[pred]))
    parts.append("  predicate isAdditionalTrustFlowStep(DataFlow::Node pred, DataFlow::Node succ) "
                 "{ none() }\n")
    parts.append("  predicate authoritySubjectOf(DataFlow::Node auth, DataFlow::Node subject) "
                 "{ none() }\n")
    parts.append("}\n")
    return "".join(parts)


def generate_facts_file(result: BindResult, language: str, out_path: str | Path) -> Path:
    """Write the generated fact module to ``out_path`` and return it."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(generate_facts(result, language), encoding="utf-8")
    return out
