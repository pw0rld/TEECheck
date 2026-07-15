"""CodeQL fact generator (iteration 3): fully-qualified (Go) / name+signature (Rust).

Emits ONE ``GeneratedTrustFacts.qll`` per repo from RESOLVED annotations. Unlike
v1's brittle exact-line ``asExpr().getLocation()`` clauses, facts are keyed on
function/parameter/call NAMES that the LLM proposed and the resolver verified —
so CodeQL resolves the real data-flow nodes and traces actual paths.

All role/kind strings come from the annotation ``role`` fields (which the
extraction prompt constrains to ``enum_registry.yml`` values), eliminating v1's
fatal enum-mismatch bug. ``authoritySubjectOf`` is populated (v1 left it none()).

Go is fully implemented (primary validation language); Rust mirrors the same
predicates via the rust-all 0.2.4 API (Call / Function / ParamList / IdentPat).
JS would emit Go-style clauses per the known gap.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from tee_audit.trustir.annotations import AnnotationKind, ResolutionStatus, TrustAnnotationSet
from tee_audit.trustir.spec import bundled_spec_dir

_LANG_IMPORT = {"go": "go", "javascript": "javascript", "rust": "rust"}

# Extra imports required after `import <lang>` so the generated facts compile.
# Go: `import go` brings `DataFlow`, `Function`, `Parameter`, `DataFlow::CallNode`
# into scope. Rust: `import rust` does NOT bring `DataFlow` into scope — the
# rust-all 0.2.4 top-level `rust.qll` does not re-export the dataflow module —
# so the generated facts need an explicit `import codeql.rust.dataflow.DataFlow`.
# (Call / Function / ParamBase / Param / IdentPat ARE brought in by `import rust`.)
_LANG_EXTRA_IMPORTS = {
    "rust": "import codeql.rust.dataflow.DataFlow\n",
}

# Categories whose values are NOT sink roles. A sink annotation carrying one of
# these roles is a mis-tag (e.g. a verifier's claim field or an authority point
# wrongly tagged as a sink) and must NOT be emitted as isTrustSink — otherwise
# FLOW-001 fires on credential PARSING (source string -> base64/protobuf decode)
# instead of a real security decision. Genuine sink roles are observable_sink_role
# values (leakage) or flow-specific roles the LLM proposes (e.g. key_derivation_input).
_NON_SINK_CATEGORIES = {
    "claim_field_role", "authority_kind", "authority_subject_role", "guard_kind",
    "binding_relation_kind", "config_source_kind", "security_mode_kind",
    "state_object_kind",
}


@functools.lru_cache(maxsize=1)
def _non_sink_roles() -> frozenset[str]:
    reg = yaml.safe_load((bundled_spec_dir() / "enum_registry.yml").read_text(encoding="utf-8"))
    roles: set[str] = set()
    for cat, vals in (reg or {}).items():
        if cat in _NON_SINK_CATEGORIES:
            roles.update(vals)
    return frozenset(roles)


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _accepted(anns):
    return [a for a in anns if a.resolution_status in (ResolutionStatus.ACCEPTED, ResolutionStatus.REPAIRED)]


# --- Go clause emitters ----------------------------------------------------- #

def _go_qual(target: str, name: str, pkg: str | None, type_name: str | None) -> str:
    """Fully-qualified Go callee/function predicate (go-all 6.0.0).

    Methods: ``target.(Method).hasQualifiedName("pkg","Type","name")`` (3-arg,
    declared on ``Method`` — the cast is required since ``CallNode.getTarget()``
    / ``Function`` are typed as ``Function``, and the 3-arg overload lives on the
    ``Method`` subtype; Scopes.qll:561-566).
    Package-level funcs: ``target.hasQualifiedName("pkg","name")`` (2-arg, on
    ``Function``/``Entity``; Scopes.qll:105-110).
    No qualifying type: name-only ``target.getName() = "name"`` (incremental;
    still correct, just not collision-free). This is the Go API — NOT Java's
    ``getDeclaringType().getSourceDeclaration()`` chain (verified go-all 6.0.0).
    """
    if pkg and type_name:
        return (
            f'{target}.(Method).hasQualifiedName("{_esc(pkg)}","{_esc(type_name)}","{_esc(name)}")'
        )
    if pkg:
        return f'{target}.hasQualifiedName("{_esc(pkg)}","{_esc(name)}")'
    return f'{target}.getName() = "{_esc(name)}"'


def _go_call_clause(param: str, value: str, name: str, pkg: str | None = None,
                    type_name: str | None = None) -> str:
    """A DataFlow::Node n that is a call to `name` (fully-qualified when pkg/type given)."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(DataFlow::CallNode c | '
        f'{_go_qual("c.getTarget()", name, pkg, type_name)} and n = c)\n'
        "    )"
    )


def _go_param_clause(param: str, value: str, fn: str, pname: str,
                     pkg: str | None = None, type_name: str | None = None) -> str:
    """A DataFlow::Node n that is parameter `pname` of function `fn`."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(Function f, Parameter p | {_go_qual("f", fn, pkg, type_name)} and '
        f'p = f.getAParameter() and p.getName() = "{_esc(pname)}" and n.asParameter() = p)\n'
        "    )"
    )


def _go_sink_clause(param: str, value: str, name: str, pkg: str | None = None,
                    type_name: str | None = None, sink_args: list[str] | None = None) -> str:
    """A DataFlow::Node n that is a (specific, when sink_args given) argument to a call to `name`."""
    if sink_args:
        positions = [str(i) for i in sink_args if str(i).lstrip("-").isdigit()]
        arg_clauses = " or ".join(f"n = c.getArgument({i})" for i in positions) if positions else ""
        if not arg_clauses:
            arg_clauses = "n = c.getAnArgument()"
    else:
        arg_clauses = "n = c.getAnArgument()"
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(DataFlow::CallNode c | '
        f'{_go_qual("c.getTarget()", name, pkg, type_name)} and {arg_clauses})\n'
        "    )"
    )


def _go_authority_subject_of_clause(name: str, subject_param: str,
                                    pkg: str | None = None, type_name: str | None = None) -> str:
    """authoritySubjectOf(auth, subject) for Go: auth is a call to `name`, subject is its `subject_param`."""
    return (
        "    exists(DataFlow::CallNode c, Function f, Parameter p |\n"
        f'      {_go_qual("c.getTarget()", name, pkg, type_name)} and '
        f'{_go_qual("f", name, pkg, type_name)} and\n'
        f'      p = f.getAParameter() and p.getName() = "{_esc(subject_param)}" and\n'
        "      auth = c and subject.asParameter() = p\n"
        "    )"
    )


def _go_suppressor_clause(suppressor: str, auth_name: str,
                          pkg: str | None = None, type_name: str | None = None) -> str:
    """hasSuppressor(n, suppressor): n is a call to the authority `auth_name` that a
    GUARD (role=`suppressor`, a guard_kind) dominates. Consumed by Guards.qll
    (hasRequiredAppraisalGuard) and the Flow/Leakage isBarrier. Conservative/
    permissive-safe by design (Guards.qll prefers false negatives)."""
    return (
        "    (\n"
        f'      suppressor = "{_esc(suppressor)}" and\n'
        f'      exists(DataFlow::CallNode c | '
        f'{_go_qual("c.getTarget()", auth_name, pkg, type_name)} and n = c)\n'
        "    )"
    )


def _go_propagator_clause(name: str, pkg: str | None = None,
                          type_name: str | None = None) -> str:
    """isAdditionalTrustFlowStep(pred, succ): taint carried from an argument of a
    call to PROPAGATOR function `name` into the call's result (IRIS taint-propagator)."""
    return (
        "    exists(DataFlow::CallNode c |\n"
        f'      {_go_qual("c.getTarget()", name, pkg, type_name)} and\n'
        "      pred = c.getAnArgument() and succ = c\n"
        "    )"
    )


# --- JavaScript clause emitters --------------------------------------------- #
#
# js-all shares the Go DataFlow API (DataFlow::CallNode, getTarget(), Parameter,
# getAParameter, getName), so the Go call/sink/authority/propagator emitters
# compile and bind correctly under `import javascript`. The ONE exception is the
# SOURCE param clause: JS fetch_params stores the enclosing fn in
# extra['func_name'] (NOT in the annotation's `signature`, which holds the param
# TYPE), and the LLM's source annotation carries only the param name. So a JS
# SOURCE binds a DataFlow::Node that is a parameter NAMED `pname` in ANY function
# (no enclosing fn available). This mirrors how Rust binds param sources, adapted
# to the js-all Parameter API.


def _js_param_clause(param: str, value: str, _fn: str, pname: str,
                     pkg: str | None = None, type_name: str | None = None) -> str:
    """JS SOURCE/SUBJECT: a DataFlow::ParameterNode for a parameter named ``pname``.

    ``_fn`` is intentionally unused — JS annotations carry only the param name
    (the enclosing fn lives in the enum's extra['func_name'], not the
    annotation), so the source binds by parameter name across all functions.
    js-all: ``Parameter.getName()`` + the builtin ``parameterNode(p)``."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(DataFlow::ParameterNode pn | pn.getParameter().getName() = "{_esc(pname)}" and n = pn)\n'
        "    )"
    )


def _js_call_clause(param: str, value: str, name: str, pkg: str | None = None,
                    type_name: str | None = None) -> str:
    """JS authority/verifier/claim-field: a DataFlow::CallNode whose callee name
    is ``name``. js-all ``CallNode.getCalleeName()``; pkg/type unused (JS has no
    static package/receiver tuple)."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(DataFlow::CallNode c | c.getCalleeName() = "{_esc(name)}" and n = c)\n'
        "    )"
    )


def _js_sink_clause(param: str, value: str, name: str, pkg: str | None = None,
                    type_name: str | None = None, sink_args: list[str] | None = None) -> str:
    """JS sink: an argument of a call to ``name`` (specific arg positions when
    ``sink_args`` given, else any argument). js-all ``CallNode.getArgument(i)``."""
    if sink_args:
        positions = [str(i) for i in sink_args if str(i).lstrip("-").isdigit()]
        arg_clauses = " or ".join(f"n = c.getArgument({i})" for i in positions) if positions else ""
        if not arg_clauses:
            arg_clauses = "n = c.getAnArgument()"
    else:
        arg_clauses = "n = c.getAnArgument()"
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(DataFlow::CallNode c | c.getCalleeName() = "{_esc(name)}" and {arg_clauses})\n'
        "    )"
    )


def _js_authority_subject_of_clause(name: str, subject_param: str,
                                    pkg: str | None = None, type_name: str | None = None) -> str:
    """JS: auth is a call to ``name``; subject is its parameter named
    ``subject_param`` (bound by name across functions — JS has no static receiver)."""
    return (
        "    exists(DataFlow::CallNode c, DataFlow::ParameterNode pn |\n"
        f'      c.getCalleeName() = "{_esc(name)}" and pn.getParameter().getName() = "{_esc(subject_param)}" and\n'
        "      auth = c and subject = pn\n"
        "    )"
    )


def _js_suppressor_clause(suppressor: str, auth_name: str,
                          pkg: str | None = None, type_name: str | None = None) -> str:
    """JS hasSuppressor: n is a call to authority ``auth_name`` dominated by a guard."""
    return (
        "    (\n"
        f'      suppressor = "{_esc(suppressor)}" and\n'
        f'      exists(DataFlow::CallNode c | c.getCalleeName() = "{_esc(auth_name)}" and n = c)\n'
        "    )"
    )


def _js_propagator_clause(name: str, pkg: str | None = None,
                          type_name: str | None = None) -> str:
    """JS taint-propagator: taint from an argument of a call to ``name`` into the
    call result (the CallNode)."""
    return (
        "    exists(DataFlow::CallNode c |\n"
        f'      c.getCalleeName() = "{_esc(name)}" and\n'
        "      pred = c.getAnArgument() and succ = c\n"
        "    )"
    )


# --- Rust clause emitters --------------------------------------------------- #
#
# rust-all 0.2.4 API differences vs Go (these emitters accommodate them):
#   - There is no `DataFlow::CallNode`. A call is the top-level `Call` class
#     (`codeql.rust.elements.Call`, brought into scope by `import rust`); its
#     name is obtained with `c.getTargetName()`. A `DataFlow::Node` wrapping the
#     call expression is recovered with `n.asExpr() = c`.
#   - There is no `Function.getAParameter()` / `Parameter.getName()` returning a
#     plain string. The chain is `Function` (extends Callable) ->
#     `getParamList().getAParamBase()` -> `ParamBase` -> cast to `Param` ->
#     `getPat()` -> cast to `IdentPat` -> `getName().getText()`.
#   - `n.asParameter()` returns a `ParamBase` (matches ParamBase directly).


def _rust_call_clause(param: str, value: str, name: str, pkg: str | None = None,
                     type_name: str | None = None) -> str:
    """A DataFlow::Node n that is a call to function `name`.

    pkg/type_name are accepted for dispatch uniformity but IGNORED (Decision-R:
    rust-all 0.2.4 has no qualification API; Rust precision comes from the
    resolver's name+arity index match, not the fact predicate)."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(Call c | c.getTargetName() = "{_esc(name)}" and n.asExpr() = c)\n'
        "    )"
    )


def _rust_param_clause(param: str, value: str, fn: str, pname: str,
                      pkg: str | None = None, type_name: str | None = None) -> str:
    """A DataFlow::Node n that is parameter `pname` of function `fn`."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        "      exists(Function f, ParamBase pb, IdentPat ip |\n"
        f'        f.getName().getText() = "{_esc(fn)}" and\n'
        "        pb = f.getParamList().getAParamBase() and\n"
        "        pb instanceof Param and ip = pb.(Param).getPat() and\n"
        f'        ip.getName().getText() = "{_esc(pname)}" and n.asParameter() = pb\n'
        "      )\n"
        "    )"
    )


def _rust_sink_clause(param: str, value: str, name: str, pkg: str | None = None,
                     type_name: str | None = None, sink_args: list[str] | None = None) -> str:
    """A DataFlow::Node n that is an argument passed to a call to function `name`."""
    return (
        "    (\n"
        f'      {param} = "{_esc(value)}" and\n'
        f'      exists(Call c | c.getTargetName() = "{_esc(name)}" and '
        "n.asExpr() = c.getAnArgument())\n"
        "    )"
    )


def _rust_authority_subject_of_clause(name: str, subject_param: str,
                                      pkg: str | None = None, type_name: str | None = None) -> str:
    """authoritySubjectOf(auth, subject): auth is a call to `name`, subject is its `subject_param`."""
    return (
        "    exists(Call c, Function f, ParamBase pb, IdentPat ip |\n"
        f'      c.getTargetName() = "{_esc(name)}" and f.getName().getText() = "{_esc(name)}" and\n'
        "      pb = f.getParamList().getAParamBase() and\n"
        "      pb instanceof Param and ip = pb.(Param).getPat() and\n"
        f'      ip.getName().getText() = "{_esc(subject_param)}" and\n'
        "      auth.asExpr() = c and subject.asParameter() = pb\n"
        "    )"
    )


def _rust_suppressor_clause(suppressor: str, auth_name: str,
                            pkg: str | None = None, type_name: str | None = None) -> str:
    """hasSuppressor(n, suppressor): n is a call to authority `auth_name` dominated by a GUARD (Rust)."""
    return (
        "    (\n"
        f'      suppressor = "{_esc(suppressor)}" and\n'
        f'      exists(Call c | c.getTargetName() = "{_esc(auth_name)}" and n.asExpr() = c)\n'
        "    )"
    )


def _rust_guard_function_clause(kind: str, name: str) -> str:
    """isGuardFunction(f, kind): f is the guard function named `name` (identity
    key, resolver-verified). The guard's protection of an authority is verified
    STRUCTURALLY by Guards.qll (CFG dominance over the authority node) — NOT by a
    name match here. The LLM `dominates` field is a write-only triage hint and is
    intentionally unused in the barrier (it must never set a finding's status)."""
    return (
        "    (\n"
        f'      kind = "{_esc(kind)}" and\n'
        f'      f.getName().getText() = "{_esc(name)}"\n'
        "    )"
    )


def _rust_propagator_clause(name: str, pkg: str | None = None,
                            type_name: str | None = None) -> str:
    """isAdditionalTrustFlowStep(pred, succ): taint from an argument of a call to
    PROPAGATOR `name` into its result (Rust; getAnArgument avoids ArgumentPosition indexing)."""
    return (
        "    exists(Call c |\n"
        f'      c.getTargetName() = "{_esc(name)}" and\n'
        "      pred.asExpr() = c.getAnArgument() and succ.asExpr() = c\n"
        "    )"
    )


def generate_facts(resolved_set: TrustAnnotationSet, language: str = "go") -> str:
    ql_import = _LANG_IMPORT.get(language, "go")
    anns = _accepted(resolved_set.annotations)

    # Language-specific clause emitters. The Go emitters use the Go DataFlow API
    # (DataFlow::CallNode / Function.getAParameter / Parameter.getName); the Rust
    # emitters use the rust-all 0.2.4 API (Call.getTargetName / ParamList /
    # IdentPat.getName().getText). See the _rust_* docstrings for the mapping.
    if language == "rust":
        call_clause = _rust_call_clause
        param_clause = _rust_param_clause
        sink_clause = _rust_sink_clause
        auth_subject_of_clause = _rust_authority_subject_of_clause
        suppressor_clause = _rust_suppressor_clause
        propagator_clause = _rust_propagator_clause
        # Rust guards are verified STRUCTURALLY (CFG dominance in Guards.qll):
        # emit only the guard-function identity fact. `dominates` is unused.
        guard_function_clause = _rust_guard_function_clause
    elif language == "javascript":
        # js-all DataFlow API differs from Go: CallNode.getCalleeName() (not
        # getTarget().getName()), no DataFlow::Node.asParameter() (use the
        # builtin parameterNode(p) for params). See the _js_* docstrings.
        call_clause = _js_call_clause
        param_clause = _js_param_clause
        sink_clause = _js_sink_clause
        auth_subject_of_clause = _js_authority_subject_of_clause
        suppressor_clause = _js_suppressor_clause
        propagator_clause = _js_propagator_clause
        guard_function_clause = None
    else:
        call_clause = _go_call_clause
        param_clause = _go_param_clause
        sink_clause = _go_sink_clause
        auth_subject_of_clause = _go_authority_subject_of_clause
        suppressor_clause = _go_suppressor_clause
        propagator_clause = _go_propagator_clause
        # Go guard barrier is still name-based (parity with the structural Rust
        # fix is a follow-up); no guard-function fact emitted for Go yet.
        guard_function_clause = None

    claim_field: list[str] = []
    authority: list[str] = []
    authority_subject: list[str] = []
    sources: list[str] = []
    sinks: list[str] = []
    auth_subject_of: list[str] = []
    suppressors: list[str] = []
    propagators: list[str] = []
    guard_functions: list[str] = []

    for a in anns:
        pkg, tname = a.declaring_type_pkg, a.declaring_type_type
        if a.kind == AnnotationKind.VERIFIER and a.claim_field_role:
            claim_field.append(call_clause("role", a.claim_field_role, a.name, pkg, tname))
        elif a.kind == AnnotationKind.AUTHORITY:
            authority.append(call_clause("kind", a.role, a.name, pkg, tname))
            if a.subject_param and a.subject_role:
                authority_subject.append(
                    param_clause("role", a.subject_role, a.name, a.subject_param, pkg, tname)
                )
                auth_subject_of.append(auth_subject_of_clause(a.name, a.subject_param, pkg, tname))
        elif a.kind == AnnotationKind.SOURCE and a.param:
            # Rust: a SOURCE labels a PARAM row, so a.name is the PARAM name and
            # the ENCLOSING FUNCTION is a.signature (param rows key the enclosing
            # fn there — verified by the resolver, which accepts only when
            # (name, signature) hits a real param item). The param clause must
            # match the param of THAT enclosing function; using a.name as the
            # function would search for a function named after the param and
            # match nothing, leaving zero source DataFlow nodes (the FLOW-kill
            # bug). Go SOURCE rows put the function in a.name, so it is unchanged.
            src_fn = a.signature if language == "rust" else a.name
            sources.append(param_clause("role", a.role, src_fn, a.param, pkg, tname))
        elif a.kind == AnnotationKind.SINK and a.role and a.role not in _non_sink_roles():
            # A sink whose role is a claim-field/authority/guard/... value is a
            # mis-tag (parsing helper, not a security decision): skip it so the
            # Flow/Leakage taint queries only fire on genuine sinks.
            sinks.append(sink_clause("role", a.role, a.name, pkg, tname, a.sink_args))
        elif a.kind == AnnotationKind.GUARD and a.role:
            # A guard of kind `role` (guard_kind enum). For Rust its protection of
            # an authority is verified STRUCTURALLY by Guards.qll (CFG dominance),
            # so we only record the guard-function identity here; the LLM
            # `dominates` field is intentionally unused (write-only triage hint —
            # it must never set a finding's status). Go still uses the legacy
            # name-based authority barrier (structural parity = follow-up).
            if guard_function_clause is not None:
                guard_functions.append(guard_function_clause(a.role, a.name))
            elif a.dominates:
                suppressors.append(suppressor_clause(a.role, a.dominates, pkg, tname))
        elif a.kind == AnnotationKind.PROPAGATOR and a.name:
            # A taint-propagator: carry taint from an argument into the call result
            # (IRIS taint-propagator; role is a taint_propagator_role enum value).
            propagators.append(propagator_clause(a.name, pkg, tname))

    def _pred(name: str, param: str, clauses: list[str]) -> str:
        body = " none()" if not clauses else "\n" + " or\n".join(clauses) + "\n"
        return f"  predicate {name}(DataFlow::Node n, string {param}) {{{body}  }}\n"

    parts = [
        "/**\n * GeneratedTrustFacts.qll (iteration 3) — GENERATED from resolved annotations.\n"
        f" * Language: {ql_import}. Go: fully-qualified hasQualifiedName facts. "
        "Rust: name+signature facts (Decision-R). FACTS ONLY.\n */\n",
        f"import {ql_import}\n",
        _LANG_EXTRA_IMPORTS.get(language, ""),
        "\nmodule GeneratedTrustFacts {\n",
        _pred("isClaimField", "role", claim_field),
        _pred("isAuthorityPoint", "kind", authority),
        _pred("isAuthoritySubject", "role", authority_subject),
        _pred("isTrustSource", "role", sources),
        _pred("isTrustSink", "role", sinks),
        _pred("hasSuppressor", "suppressor", suppressors),
    ]
    # isGuardFunction is Function-typed (not DataFlow::Node), so emit it directly.
    gf_body = " none()" if not guard_functions else "\n" + " or\n".join(guard_functions) + "\n"
    parts.append(
        f"  predicate isGuardFunction(Function f, string kind) {{{gf_body}  }}\n"
    )
    # isAdditionalTrustFlowStep has no string column; assemble it directly.
    prop_body = " none()" if not propagators else "\n" + " or\n".join(propagators) + "\n"
    parts.append(
        f"  predicate isAdditionalTrustFlowStep(DataFlow::Node pred, DataFlow::Node succ) {{{prop_body}  }}\n"
    )
    asof_body = " none()" if not auth_subject_of else "\n" + " or\n".join(auth_subject_of) + "\n"
    parts.append(
        f"  predicate authoritySubjectOf(DataFlow::Node auth, DataFlow::Node subject) {{{asof_body}  }}\n"
    )
    parts.append("}\n")
    return "".join(parts)


def generate_facts_file(resolved_set: TrustAnnotationSet, language: str, out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(generate_facts(resolved_set, language), encoding="utf-8")
    return out


__all__ = ["generate_facts", "generate_facts_file"]
