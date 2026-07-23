"""Tests for the iteration-3 index resolver (verify->reject against EnumItemIndex)."""

from __future__ import annotations

from tee_audit.trustir.annotations import (
    AnnotationKind,
    ResolutionStatus,
    TrustAnnotation,
    TrustAnnotationSet,
)
from tee_audit.trustir.enumeration import EnumItem, EnumItemIndex
from tee_audit.trustir.resolver.index_resolver import resolve_against_index


def _set(anns):
    return TrustAnnotationSet(repo="r", language="go", annotations=anns)


def _ann(kind, role, name, **kw):
    return TrustAnnotation(id=f"a-{name}", kind=kind, role=role, name=name, **kw)


def test_accept_go_inherits_location():
    idx = EnumItemIndex(
        [EnumItem("call", "Call", "core/tx.go", 42,
                  declaring_type_pkg="suave/confidential", declaring_type_type="ConfidentialEthBackend",
                  signature="Call(a,b,c)", arg_count=3)],
        "go",
    )
    a = _ann(AnnotationKind.SINK, "enclave_call_input", "Call",
             declaring_type_pkg="suave/confidential", declaring_type_type="ConfidentialEthBackend",
             sink_args=["1"])
    out = resolve_against_index(_set([a]), idx, "go")
    assert out.annotations[0].resolution_status is ResolutionStatus.ACCEPTED
    assert out.annotations[0].resolved_file == "core/tx.go"
    assert out.annotations[0].resolved_line == 42


def test_reject_absent_ref():
    idx = EnumItemIndex(
        [EnumItem("call", "Call", "c.go", 1, declaring_type_pkg="suave", declaring_type_type="ConfidentialEthBackend")],
        "go",
    )
    a = _ann(AnnotationKind.SINK, "enclave_call_input", "Call",
             declaring_type_pkg="geth/vm", declaring_type_type="VMEnv")  # different type -> not in index
    out = resolve_against_index(_set([a]), idx, "go")
    assert out.annotations[0].resolution_status is ResolutionStatus.REJECTED
    assert "ref_not_found" in (out.annotations[0].resolution_note or "")


def test_reject_out_of_catalog_role():
    idx = EnumItemIndex([EnumItem("function", "verifyQuote", "v.go", 1)], "go")
    a = _ann(AnnotationKind.SINK, "totally_invented_role", "verifyQuote")
    out = resolve_against_index(_set([a]), idx, "go")
    assert out.annotations[0].resolution_status is ResolutionStatus.REJECTED
    assert "role_not_in_catalog" in (out.annotations[0].resolution_note or "")


def test_reject_sink_args_out_of_range():
    idx = EnumItemIndex(
        [EnumItem("call", "Call", "c.go", 1,
                  declaring_type_pkg="suave", declaring_type_type="ConfidentialEthBackend", arg_count=2)],
        "go",
    )
    a = _ann(AnnotationKind.SINK, "enclave_call_input", "Call",
             declaring_type_pkg="suave.ConfidentialEthBackend".split(".")[0],
             declaring_type_type="ConfidentialEthBackend", sink_args=["5"])
    # fix declaring_type to match index key
    a.declaring_type_pkg = "suave"
    out = resolve_against_index(_set([a]), idx, "go")
    assert out.annotations[0].resolution_status is ResolutionStatus.REJECTED
    assert "sink_args_out_of_range" in (out.annotations[0].resolution_note or "")


def test_collision_isolation_go():
    """Two same-name/different-type sinks: each resolves only against its own type."""
    idx = EnumItemIndex([
        EnumItem("call", "Call", "suave/tx.go", 10, declaring_type_pkg="suave", declaring_type_type="ConfidentialEthBackend", arg_count=3),
        EnumItem("call", "Call", "vm/vm.go", 20, declaring_type_pkg="geth", declaring_type_type="VMEnv", arg_count=2),
    ], "go")
    suave = _ann(AnnotationKind.SINK, "enclave_call_input", "Call",
                 declaring_type_pkg="suave", declaring_type_type="ConfidentialEthBackend")
    geth = _ann(AnnotationKind.SINK, "enclave_call_input", "Call",
                declaring_type_pkg="geth", declaring_type_type="VMEnv")
    out = resolve_against_index(_set([suave, geth]), idx, "go")
    by_type = {a.declaring_type_type: a for a in out.annotations}
    assert by_type["ConfidentialEthBackend"].resolved_line == 10
    assert by_type["VMEnv"].resolved_line == 20
    assert all(a.resolution_status is ResolutionStatus.ACCEPTED for a in out.annotations)


def test_rust_uses_name_signature_key():
    idx = EnumItemIndex([
        EnumItem("call", "verify", "x.rs", 5, signature="1"),  # arity as signature
        EnumItem("call", "verify", "y.rs", 9, signature="2"),
    ], "rust")
    a = _ann(AnnotationKind.SINK, "access_control_decision", "verify", signature="2")
    out = resolve_against_index(_set([a]), idx, "rust")
    assert out.annotations[0].resolution_status is ResolutionStatus.ACCEPTED
    assert out.annotations[0].resolved_line == 9  # matched the arity-2 one


def test_rust_name_grounding_recovers_misplaced_name_signature():
    """The real dcap-qvl bug: the LLM emits the function NAME as the signature
    instead of the arity, so the exact ``(name, signature)`` key misses. Name
    grounding recovers it and INHERITS the arity + location from CodeQL — the
    LLM only supplied the semantic name + role."""
    idx = EnumItemIndex([
        EnumItem("call", "verify_qe_report_signature", "src/verify.rs", 913, signature="2"),
        EnumItem("function", "verify_qe_report_signature", "src/verify.rs", 464, signature="2"),
    ], "rust")
    a = _ann(AnnotationKind.GUARD, "quote_signature_verification",
             "verify_qe_report_signature", signature="verify_qe_report_signature")
    out = resolve_against_index(_set([a]), idx, "rust")
    got = out.annotations[0]
    assert got.resolution_status is ResolutionStatus.ACCEPTED
    assert got.signature == "2"                       # arity inherited from CodeQL
    assert got.resolved_file == "src/verify.rs"
    assert got.resolution_note.startswith("index_resolved(name_grounding")


def test_rust_name_grounding_prefers_function_def():
    """When a name has both call sites and a definition, ground to the def."""
    idx = EnumItemIndex([
        EnumItem("call", "verify", "a.rs", 10, signature="2"),
        EnumItem("call", "verify", "b.rs", 20, signature="2"),
        EnumItem("function", "verify", "c.rs", 5, signature="2"),
    ], "rust")
    a = _ann(AnnotationKind.GUARD, "quote_signature_verification", "verify", signature="verify")
    out = resolve_against_index(_set([a]), idx, "rust")
    got = out.annotations[0]
    assert got.resolution_status is ResolutionStatus.ACCEPTED
    assert got.resolved_line == 5                     # the function definition
    assert got.signature == "2"


def test_rust_name_grounding_rejects_genuine_ambiguity():
    """Two definitions, distinct arities, no disambiguating hint -> reject."""
    idx = EnumItemIndex([
        EnumItem("function", "parse", "a.rs", 1, signature="1"),
        EnumItem("function", "parse", "b.rs", 2, signature="2"),
    ], "rust")
    a = _ann(AnnotationKind.GUARD, "quote_signature_verification", "parse", signature="parse")
    out = resolve_against_index(_set([a]), idx, "rust")
    assert out.annotations[0].resolution_status is ResolutionStatus.REJECTED
    assert "ref_not_found" in (out.annotations[0].resolution_note or "")


def test_rust_param_source_not_name_grounded():
    """A genuine param SOURCE (param != name) needs its enclosing-fn signature;
    a bare param name is ambiguous across functions, so it is never name-grounded
    (stays strict). A wrong enclosing fn -> rejected."""
    idx = EnumItemIndex([
        EnumItem("param", "user_data", "ffi.rs", 286, signature="dcap_parse_quote_cb"),
        EnumItem("param", "user_data", "ffi.rs", 440, signature="dcap_get_collateral_cb"),
    ], "rust")
    a = _ann(AnnotationKind.SOURCE, "external_attestation_input", "ffi_cb",
             signature="wrong_fn", param="user_data")
    out = resolve_against_index(_set([a]), idx, "rust")
    assert out.annotations[0].resolution_status is ResolutionStatus.REJECTED


def test_rust_param_source_recovers_enclosing_fn_in_name():
    """LLM shape variant: name=enclosing-fn, signature=enclosing-fn, param=param.
    The resolver reconstructs (param, enclosing-fn) and grounds exactly, matching
    the fact generator's (a.param, a.signature) SOURCE clause."""
    idx = EnumItemIndex([
        EnumItem("param", "url", "net.rs", 12, signature="http_get"),
    ], "rust")
    a = _ann(AnnotationKind.SOURCE, "host_input", "http_get",
             signature="http_get", param="url")
    out = resolve_against_index(_set([a]), idx, "rust")
    got = out.annotations[0]
    assert got.resolution_status is ResolutionStatus.ACCEPTED
    assert got.resolved_line == 12


def test_rejected_never_accepted_by_generator():
    """Rejected annotations are dropped by the generator's _accepted filter."""
    from tee_audit.trustir.generator.annotation_facts import _accepted
    idx = EnumItemIndex([EnumItem("call", "X", "c.go", 1, declaring_type_pkg="p", declaring_type_type="T")], "go")
    a = _ann(AnnotationKind.SINK, "enclave_call_input", "X",
             declaring_type_pkg="other", declaring_type_type="Wrong")  # will be rejected
    resolve_against_index(_set([a]), idx, "go")
    assert a.resolution_status is ResolutionStatus.REJECTED
    assert _accepted([a]) == []  # never reaches facts
