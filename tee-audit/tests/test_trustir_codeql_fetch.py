"""Pure-Python tests for the BQRS->EnumItem mapping (US-004).

These test the decoding/mapping logic without a live CodeQL run (which needs the
fetch .ql + a DB). The live run is exercised separately against suave-geth-go.
"""

from __future__ import annotations

from tee_audit.trustir.codeql_fetch import _find_tuples, _scalar, rows_to_items


def test_scalar_bare():
    assert _scalar("Call") == "Call"
    assert _scalar(3) == 3


def test_scalar_wrapped_str_and_int():
    assert _scalar({"str": "Call"}) == "Call"
    assert _scalar({"i": 3}) == 3


def test_scalar_entity_dict_is_none():
    assert _scalar({"label": "x", "location": "y"}) is None


def test_find_tuples_locates_nested():
    doc = {"results": {"#select": {"columns": [{"name": "a"}],
                                   "tuples": [["x"]]}}}
    cols, tuples = _find_tuples(doc)
    assert tuples == [["x"]]


def test_rows_to_items_go_calls_bare():
    cols_order = ["_", "name", "pkg", "type_name", "arg_count", "signature", "file", "line"]
    tup = ["<elem>", "Call", "suave/confidential", "ConfidentialEthBackend", 3, "Call(a,b,c)", "core/tx.go", 10]
    items = rows_to_items("fetch_calls", "go", [tup])
    assert len(items) == 1
    it = items[0]
    assert it.kind == "call" and it.name == "Call"
    assert it.declaring_type_pkg == "suave/confidential"
    assert it.declaring_type_type == "ConfidentialEthBackend"
    assert it.declaring_type == "suave/confidential.ConfidentialEthBackend"
    assert it.arg_count == 3 and it.signature == "Call(a,b,c)"
    assert it.file == "core/tx.go" and it.line == 10


def test_rows_to_items_go_calls_wrapped():
    # BQRS tuples often wrap scalars as {"str": ...} / {"i": ...}.
    tup = [{"label": "x"}, {"str": "Call"}, {"str": "p"}, {"str": "T"},
           {"i": 2}, {"str": "sig"}, {"str": "f.go"}, {"i": 7}]
    items = rows_to_items("fetch_calls", "go", [tup])
    assert items[0].name == "Call" and items[0].arg_count == 2 and items[0].line == 7


def test_rows_to_items_rust_calls_no_declaring_type():
    # US-003 Rust fetch emits [entity, "call_site|callee=..|arg_count=..|file=..|line=.."].
    tup = ["<e>", "call_site|callee=verify|arg_count=1|file=x.rs|line=5"]
    items = rows_to_items("fetch_calls", "rust", [tup])
    assert items[0].name == "verify"
    assert items[0].declaring_type_pkg is None and items[0].declaring_type_type is None
    assert items[0].signature == "1"  # arity as the disambiguator
    assert items[0].arg_count == 1 and items[0].line == 5


def test_rows_to_items_rust_functions_and_params_blob():
    fn_tup = ["<e>", "function_def|name=load_key|param_count=2|file=k.rs|line=12"]
    f = rows_to_items("fetch_functions", "rust", [fn_tup])[0]
    assert f.name == "load_key" and f.signature == "2" and f.line == 12
    p_tup = ["<e>", "param|name=path|enclosing_fn=load_key|file=k.rs|line=12"]
    p = rows_to_items("fetch_params", "rust", [p_tup])[0]
    assert p.name == "path" and p.signature == "load_key"  # enclosing fn disambiguates


def test_rows_to_items_skips_unnamed():
    # A row whose name column is empty is dropped.
    tup = ["<e>", "", "p", "T", 1, "s", "f.go", 1]
    assert rows_to_items("fetch_calls", "go", [tup]) == []


def test_rows_to_items_go_params_and_field_reads():
    param_tup = ["<e>", "ctx", "Handle", "pkg", "Server", "context.Context", {"i": 0}, "s.go", {"i": 12}]
    p = rows_to_items("fetch_params", "go", [param_tup])[0]
    assert p.kind == "param" and p.name == "ctx" and p.declaring_type_type == "Server"
    field_tup = ["<e>", "AllowedPeekers", "Record", "Retrieve", "pkg", "e.go", {"i": 30}]
    f = rows_to_items("fetch_field_reads", "go", [field_tup])[0]
    assert f.kind == "field_read" and f.name == "AllowedPeekers" and f.declaring_type_type == "Record"
