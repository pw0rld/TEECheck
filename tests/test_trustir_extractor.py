"""Tests for the TrustIR iteration-3 IRIS extractor (enumerate-then-classify).

Replaces the iteration-2 zone-extractor tests. The LLM no longer proposes
file:line/id/zones — CodeQL enumerates the real API surface (here faked via an
injected ``run_fetch_queries`` result list), the LLM only labels a subset with
role + sink_args + declaring_type, and a deterministic catalog gate drops any
role outside ``enum_registry.yml``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tee_audit.trustir.annotations import AnnotationKind, TrustAnnotationSet
from tee_audit.trustir.extractor import classify_repo, extract_repo
from tee_audit.trustir.extractor.enumerate_classify import (
    _build_annotation,
    _make_batches,
    _parse_json_array,
    _role_to_kind_map,
    _slug,
    path_in_scope,
)
from tee_audit.trustir.enumeration import EnumItem, EnumItemIndex

PROMPTS_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "tee_audit" / "prompts"
)
CLASSIFY_PROMPT = PROMPTS_DIR / "trustir_classify.md"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeClient:
    """Fake LLM client: ``complete`` returns a canned JSON array.

    Captures every call so tests can assert the prompt content / batching.
    """

    def __init__(self, payload: str) -> None:
        self._payload = payload
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        self.calls.append((system, user))
        return self._payload

    # unused but satisfies the LLMClient protocol surface if anything pokes it
    def complete_structured(self, system, user, schema, temperature: float = 0):  # noqa: ANN001
        raise AssertionError("classify_repo must use complete(), not structured")

    def count_tokens(self, text: str) -> int:
        return len(text) // 4


def _sample_items() -> list[EnumItem]:
    """A tiny fixture list of EnumItems standing in for run_fetch_queries."""
    return [
        EnumItem(
            kind="call",
            name="Call",
            file="eth/api_backend.go",
            line=472,
            declaring_type_pkg="github.com/flashbots/suave-geth/eth",
            declaring_type_type="EthAPIBackend",
            signature="Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error)",
            arg_count=3,
        ),
        EnumItem(
            kind="function",
            name="VerifyQuote",
            file="attest/verify.go",
            line=42,
            declaring_type_pkg="github.com/example/tee/attest",
            declaring_type_type="Verifier",
            signature="VerifyQuote(quote []byte) (Report, error)",
        ),
        EnumItem(
            kind="function",
            name="releaseKey",
            file="keyrelease/release.go",
            line=88,
            declaring_type_pkg="github.com/example/tee/keyrelease",
            declaring_type_type="KeyRelease",
            signature="releaseKey(agentID string) []byte",
        ),
        EnumItem(
            kind="function",
            name="utilFunc",
            file="util/util.go",
            line=10,
            declaring_type_pkg="github.com/example/tee/util",
            declaring_type_type="Util",
            signature="utilFunc(x int) int",
        ),
    ]


@pytest.fixture
def fake_items() -> list[EnumItem]:
    return _sample_items()


@pytest.fixture
def patched_fetch(monkeypatch, fake_items):
    """Patch run_fetch_queries inside enumerate_classify to return fake_items."""
    def _fake_run_fetch(db_path, language, codeql_path, workdir):  # noqa: ANN001
        Path(workdir).mkdir(parents=True, exist_ok=True)
        (Path(workdir) / "fetch_exclusion.log").write_text("# fake\n", encoding="utf-8")
        return list(fake_items)

    from tee_audit.trustir.extractor import enumerate_classify as ec

    monkeypatch.setattr(ec, "run_fetch_queries", _fake_run_fetch)
    return _fake_run_fetch


# --------------------------------------------------------------------------- #
# Catalog gate + kind inference (pure, no LLM)
# --------------------------------------------------------------------------- #


def test_role_to_kind_maps_every_catalog_category() -> None:
    mapping = _role_to_kind_map()
    # one spot-check per category
    assert mapping["host_input"] is AnnotationKind.SOURCE
    assert mapping["enclave_call_input"] is AnnotationKind.SINK
    assert mapping["rpc_response"] is AnnotationKind.SINK  # observable_sink_role
    assert mapping["key_release"] is AnnotationKind.AUTHORITY
    assert mapping["quote_signature_verification"] is AnnotationKind.GUARD
    assert mapping["encoding_passthrough"] is AnnotationKind.PROPAGATOR
    assert mapping["attested_public_key"] is AnnotationKind.VERIFIER


def test_build_annotation_drops_role_not_in_catalog() -> None:
    mapping = _role_to_kind_map()
    counter: dict[str, int] = {}
    bad = _build_annotation(
        {"name": "foo", "role": "INVENTED_ROLE"}, mapping, counter=counter
    )
    assert bad is None  # catalog gate
    assert counter == {}  # no id assigned on drop


def test_build_annotation_assigns_deterministic_id_without_file_line() -> None:
    mapping = _role_to_kind_map()
    counter: dict[str, int] = {}
    ann = _build_annotation(
        {
            "name": "Call",
            "declaring_type_pkg": "github.com/x/y",
            "declaring_type_type": "Backend",
            "role": "enclave_call_input",
            "sink_args": ["2", "input"],
            "signature": "Call(ctx, input)",
            # The LLM MUST NOT emit these; if it does, we MUST ignore them.
            "file": "should/be/ignored.go",
            "line": 999,
            "id": "should-be-ignored",
        },
        mapping,
        counter=counter,
    )
    assert ann is not None
    # id assigned deterministically (NOT copied from LLM)
    assert ann.id == "sink-call-1"
    # NO file/line copied from the LLM — CodeQL owns location
    assert ann.file is None
    assert ann.line is None
    # kind inferred from role category
    assert ann.kind is AnnotationKind.SINK
    assert ann.sink_args == ["2", "input"]
    assert ann.declaring_type_pkg == "github.com/x/y"
    assert ann.declaring_type_type == "Backend"


def test_build_annotation_copies_authority_extras() -> None:
    mapping = _role_to_kind_map()
    ann = _build_annotation(
        {
            "name": "releaseKey",
            "declaring_type_pkg": "p",
            "declaring_type_type": "KeyRelease",
            "role": "key_release",
            "signature": "releaseKey(agentID string)",
            "subject_param": "agentID",
            "subject_role": "key_release_recipient",
            "protected_asset": "session_key",
        },
        mapping,
        counter={},
    )
    assert ann is not None
    assert ann.kind is AnnotationKind.AUTHORITY
    assert ann.subject_param == "agentID"
    assert ann.subject_role == "key_release_recipient"
    assert ann.protected_asset == "session_key"


def test_slug_handles_punctuation_and_empty() -> None:
    assert _slug("Call") == "call"
    assert _slug("Verify_Quote!") == "verify-quote"
    assert _slug("") == "anon"


# --------------------------------------------------------------------------- #
# JSON parsing
# --------------------------------------------------------------------------- #


def test_parse_json_array_handles_fences_and_envelope() -> None:
    bare = '[{"name":"a","role":"host_input"}]'
    assert _parse_json_array(bare) == [{"name": "a", "role": "host_input"}]

    fenced = "```json\n" + bare + "\n```"
    assert _parse_json_array(fenced) == [{"name": "a", "role": "host_input"}]

    envelope = '{"annotations": ' + bare + "}"
    assert _parse_json_array(envelope) == [{"name": "a", "role": "host_input"}]

    assert _parse_json_array("") == []
    assert _parse_json_array("not json at all") == []


# --------------------------------------------------------------------------- #
# Batching
# --------------------------------------------------------------------------- #


def test_make_batches_caps_row_count(fake_items: list[EnumItem]) -> None:
    # 4 items, cap at 200 -> 1 batch
    batches = _make_batches(fake_items)
    assert len(batches) == 1
    assert len(batches[0]) == 4


def test_make_batches_splits_on_row_cap(monkeypatch) -> None:
    from tee_audit.trustir.extractor import enumerate_classify as ec

    monkeypatch.setattr(ec, "_MAX_ROWS_PER_BATCH", 2)
    items = [
        EnumItem(kind="function", name=f"f{i}", file="a.go", line=i,
                 declaring_type_pkg="p", declaring_type_type="T")
        for i in range(5)
    ]
    batches = _make_batches(items)
    assert [len(b) for b in batches] == [2, 2, 1]


# --------------------------------------------------------------------------- #
# classify_repo (full smoke test with injected fake client + patched fetch)
# --------------------------------------------------------------------------- #


def test_classify_repo_runs_catalog_gate_and_assigns_kinds(
    patched_fetch, tmp_path: Path
) -> None:
    """End-to-end: fetch (faked) + LLM (canned JSON) + catalog gate + ids.

    Canned payload mixes one VALID role, one INVALID role (must be dropped),
    and one VALID with sink_args.
    """
    payload = json.dumps(
        [
            {
                "name": "Call",
                "declaring_type_pkg": "github.com/flashbots/suave-geth/eth",
                "declaring_type_type": "EthAPIBackend",
                "role": "enclave_call_input",
                "sink_args": ["2", "input"],
                "signature": "Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error)",
                "reasoning": "input reaches confidential compute",
            },
            {
                "name": "VerifyQuote",
                "declaring_type_pkg": "github.com/example/tee/attest",
                "declaring_type_type": "Verifier",
                "role": "INVENTED_ROLE",  # MUST be dropped by the catalog gate
                "reasoning": "should not survive",
            },
            {
                "name": "releaseKey",
                "declaring_type_pkg": "github.com/example/tee/keyrelease",
                "declaring_type_type": "KeyRelease",
                "role": "key_release",
                "signature": "releaseKey(agentID string) []byte",
                "subject_param": "agentID",
                "subject_role": "key_release_recipient",
                "reasoning": "authority",
            },
        ]
    )
    client = FakeClient(payload)

    ann_set, index = classify_repo(
        repo_path=tmp_path / "fake-repo",
        language="go",
        codeql_path=Path("/usr/bin/codeql"),  # never invoked (fetch is patched)
        workdir=tmp_path / "work",
        db_path=tmp_path / "fake-db",
        client=client,
    )

    # fetch ran once, wrote exclusion log
    assert (tmp_path / "work" / "fetch_exclusion.log").is_file()

    assert isinstance(ann_set, TrustAnnotationSet)
    assert isinstance(index, EnumItemIndex)
    assert len(index) == 4  # all faked EnumItems indexed

    # catalog gate dropped the INVENTED_ROLE entry
    names = [a.name for a in ann_set.annotations]
    assert "Call" in names
    assert "releaseKey" in names
    assert "VerifyQuote" not in names  # gated out

    # kinds inferred correctly
    by_name = {a.name: a for a in ann_set.annotations}
    assert by_name["Call"].kind is AnnotationKind.SINK
    assert by_name["Call"].sink_args == ["2", "input"]
    assert by_name["releaseKey"].kind is AnnotationKind.AUTHORITY
    assert by_name["releaseKey"].subject_role == "key_release_recipient"

    # ids are deterministic and unique; LLM never set them
    ids = [a.id for a in ann_set.annotations]
    assert len(set(ids)) == len(ids)
    assert all(not i.startswith("should") for i in ids)

    # NO LLM-supplied file/line/id leaks through (LLM owns none of these)
    for a in ann_set.annotations:
        assert a.file is None
        assert a.line is None

    # exactly one LLM call (single batch of 4 items)
    assert len(client.calls) == 1
    system, user = client.calls[0]
    assert "classification layer" in system
    # the prompt carried the enumeration + family + language
    assert "Call" in user
    assert "TWE" in user or "go" in user


def test_classify_repo_with_empty_envelope_returns_empty_set(
    patched_fetch, tmp_path: Path
) -> None:
    client = FakeClient("[]")
    ann_set, _ = classify_repo(
        repo_path=tmp_path / "r",
        language="go",
        codeql_path=Path("/usr/bin/codeql"),
        workdir=tmp_path / "w",
        db_path=tmp_path / "fake-db",
        client=client,
    )
    assert ann_set.annotations == []


def test_classify_repo_swallows_one_bad_batch(patched_fetch, tmp_path: Path, caplog) -> None:
    """A batch whose LLM call raises must not abort the whole run."""
    payload = json.dumps([{"name": "releaseKey", "role": "key_release"}])

    class FlakyClient:
        def __init__(self):
            self.n = 0

        def complete(self, system, user, temperature: float = 0):
            self.n += 1
            # pretend every call raises once, then succeeds — but with one batch
            # we only get one call. Instead, raise to prove the run survives.
            raise RuntimeError("boom")

        def count_tokens(self, text):
            return 0

    client = FlakyClient()
    ann_set, _ = classify_repo(
        repo_path=tmp_path / "r",
        language="go",
        codeql_path=Path("/usr/bin/codeql"),
        workdir=tmp_path / "w",
        db_path=tmp_path / "fake-db",
        client=client,  # type: ignore[arg-type]
    )
    # bad batch swallowed -> empty set, no crash
    assert ann_set.annotations == []


# --------------------------------------------------------------------------- #
# extract_repo wrapper (legacy two-tuple compatibility)
# --------------------------------------------------------------------------- #


def test_extract_repo_returns_two_tuple_and_persists(
    patched_fetch, tmp_path: Path
) -> None:
    payload = json.dumps(
        [{"name": "Call", "role": "host_input", "param": "input"}]
    )
    client = FakeClient(payload)
    results = tmp_path / "out"
    ann_set, legacy = extract_repo(
        client=client,
        repo_path=tmp_path / "r",
        language="go",
        results_dir=results,
        codeql_path=Path("/usr/bin/codeql"),  # not invoked (fetch patched)
        db_path=tmp_path / "fake-db",
    )
    assert isinstance(ann_set, TrustAnnotationSet)
    # legacy second slot is now an empty dict (zone_map retired)
    assert legacy == {}
    assert (results / "annotations.json").is_file()
    assert len(ann_set.annotations) == 1
    assert ann_set.annotations[0].kind is AnnotationKind.SOURCE


# --------------------------------------------------------------------------- #
# Prompt-text discipline (string assertions on the new prompt file)
# --------------------------------------------------------------------------- #


def test_classify_prompt_requires_role_and_forbids_file_line_id_status() -> None:
    text = CLASSIFY_PROMPT.read_text()

    # role discipline
    assert "use ONLY these strings" in text
    assert "catalog gate" in text.lower()

    # forbidden LLM outputs
    assert "NEVER" in text
    assert "emit `file`, `line`, or `id`" in text
    assert "status" in text.lower()

    # the catalog values are listed verbatim
    assert "enclave_call_input" in text
    assert "host_input" in text
    assert "key_release" in text
    assert "quote_signature_verification" in text
    assert "encoding_passthrough" in text
    assert "attested_public_key" in text

    # placeholders present
    assert "{{enumeration}}" in text
    assert "{{twe_family}}" in text
    assert "{{language}}" in text
    assert "{{repo_summary}}" in text

    # strict JSON list output requirement
    assert "JSON array" in text


# --------------------------------------------------------------------------- #
# Iteration-3 precision fixes: non-ident marker filter + dedup + raw persist
# --------------------------------------------------------------------------- #


def test_build_annotation_drops_non_ident_marker_name() -> None:
    """Anonymity markers (Rust fetch sentinels) never become annotations."""
    mapping = _role_to_kind_map()
    for marker in ("<non-ident-pat>", "<none>", ""):
        assert _build_annotation({"name": marker, "role": "host_input"}, mapping, counter={}) is None


def test_droppable_excludes_serde_codec_derive_generated_symbols() -> None:
    """Macro-expanded symbols beyond PyO3/clap/wasm — serde derive, parity
    SCALE-codec, derive_more/pin-project, PyO3 module-init internals — are
    dropped pre-LLM so the LLM labels real verifier logic, not serialization
    plumbing. Excluding them must NOT depend on LLM variance."""
    from tee_audit.trustir.extractor.enumerate_classify import _is_droppable

    generated = [
        "__deserializer", "__serializer", "__deserialize", "__serialize",
        "__codec_input_edqy", "__codec_dest", "__codec_hidden",
        "__derive_more", "__priv_concatenate", "__pyo3_init", "__pyo3_pymodule",
        # PyO3/clap/wasm (unchanged) still caught.
        "__pyfunction_py_verify", "__clap_arg_matches", "__wasm_bindgen_f",
    ]
    for name in generated:
        assert _is_droppable(name), f"{name!r} should be droppable"

    # Trait methods/real identifiers (incl. the non-prefixed serde method names)
    # must NOT be excluded — only the __-prefixed generated impl symbols are.
    legit = [
        "verify_qe_report_signature", "dcap_get_collateral_cb", "user_data",
        "quote", "deserialize", "serialize", "visit_seq", "value", "__init",
    ]
    for name in legit:
        assert not _is_droppable(name), f"{name!r} must NOT be droppable"


def test_link_guards_to_authorities_fills_dominates_from_authority_set() -> None:
    """Second-pass linking fills `dominates` for guards lacking it, picking ONLY
    from the authority set (hallucinated authorities dropped); guards that
    already carry `dominates` are untouched; one LLM call total."""
    from tee_audit.trustir.annotations import TrustAnnotation
    from tee_audit.trustir.extractor.enumerate_classify import link_guards_to_authorities

    anns = [
        TrustAnnotation(id="g1", kind=AnnotationKind.GUARD, role="quote_signature_verification", name="verify_sig"),
        TrustAnnotation(id="g2", kind=AnnotationKind.GUARD, role="collateral_freshness_check", name="fresh"),
        TrustAnnotation(id="g3", kind=AnnotationKind.GUARD, role="crl_revocation_check", name="crl", dominates="keep_me"),
        TrustAnnotation(id="a1", kind=AnnotationKind.AUTHORITY, role="proof_acceptance", name="run_verify"),
        TrustAnnotation(id="a2", kind=AnnotationKind.AUTHORITY, role="key_release", name="release_key"),
    ]
    s = TrustAnnotationSet(repo="r", language="rust", annotations=anns)
    # LLM picks: g1 -> a real authority (accepted); g2 -> a bogus name (dropped).
    client = FakeClient(json.dumps({"verify_sig": "run_verify", "fresh": "bogus_auth"}))

    out = link_guards_to_authorities(client, s, language="rust", repo_summary="r", twe_family="ATTEST")
    by = {a.name: a for a in out.annotations}
    assert by["verify_sig"].dominates == "run_verify"   # filled from the authority set
    assert by["fresh"].dominates is None                 # hallucinated authority dropped
    assert by["crl"].dominates == "keep_me"              # already set -> untouched
    assert len(client.calls) == 1                         # exactly one linking call


def test_link_guards_to_authorities_noops_without_authorities() -> None:
    """No authorities (or no guards lacking dominates) -> no LLM call."""
    from tee_audit.trustir.annotations import TrustAnnotation
    from tee_audit.trustir.extractor.enumerate_classify import link_guards_to_authorities

    anns = [TrustAnnotation(id="g1", kind=AnnotationKind.GUARD, role="quote_signature_verification", name="g")]
    s = TrustAnnotationSet(repo="r", language="rust", annotations=anns)
    client = FakeClient("[]")
    out = link_guards_to_authorities(client, s, language="rust", repo_summary="r", twe_family="ATTEST")
    assert len(client.calls) == 0   # no authorities -> early no-op
    assert out.annotations[0].dominates is None


def test_classify_repo_drops_marker_items_and_dedups(monkeypatch, tmp_path: Path) -> None:
    """Pre-LLM filter drops marker-named items; exact-duplicate annotations collapse."""
    from tee_audit.trustir.extractor import enumerate_classify as ec

    marker_items = [
        EnumItem(kind="param", name="<non-ident-pat>", file="x.rs", line=1, signature="fetch"),
        EnumItem(kind="field_read", name="<none>", file="x.rs", line=2, signature="g"),
    ]

    def _fake_fetch(db_path, language, codeql_path, workdir):  # noqa: ANN001
        Path(workdir).mkdir(parents=True, exist_ok=True)
        (Path(workdir) / "fetch_exclusion.log").write_text("# f\n", encoding="utf-8")
        return _sample_items() + marker_items

    monkeypatch.setattr(ec, "run_fetch_queries", _fake_fetch)

    payload = json.dumps([
        {"name": "Call", "declaring_type_pkg": "p", "declaring_type_type": "B",
         "role": "enclave_call_input", "sink_args": ["2"]},
        {"name": "Call", "declaring_type_pkg": "p", "declaring_type_type": "B",
         "role": "enclave_call_input", "sink_args": ["2"]},  # exact duplicate
        {"name": "<non-ident-pat>", "role": "host_input"},  # LLM echoes a marker
    ])
    client = FakeClient(payload)

    ann_set, index = classify_repo(
        repo_path=tmp_path / "r", language="go",
        codeql_path=Path("/usr/bin/codeql"), workdir=tmp_path / "w",
        db_path=tmp_path / "db", client=client,
    )

    names = [a.name for a in ann_set.annotations]
    assert "<non-ident-pat>" not in names
    # dedup: the two identical Call annotations collapse to one
    assert sum(1 for n in names if n == "Call") == 1
    # markers were filtered before indexing too
    assert all(it.name not in ("<non-ident-pat>", "<none>") for it in index.all_items())


def test_classify_repo_persists_raw_artifacts(patched_fetch, tmp_path: Path) -> None:
    """persist_dir writes the pre-resolve enumeration + LLM classifications."""
    payload = json.dumps([{"name": "Call", "role": "host_input", "param": "input"}])
    client = FakeClient(payload)
    raw = tmp_path / "raw"

    classify_repo(
        repo_path=tmp_path / "r", language="go",
        codeql_path=Path("/usr/bin/codeql"), workdir=tmp_path / "w",
        db_path=tmp_path / "db", client=client, persist_dir=raw,
    )

    assert (raw / "enum_items.json").is_file()
    assert (raw / "annotations.raw.json").is_file()
    ei = json.loads((raw / "enum_items.json").read_text(encoding="utf-8"))
    assert ei and {"name", "signature", "signature_text"} <= set(ei[0])
    ar = json.loads((raw / "annotations.raw.json").read_text(encoding="utf-8"))
    assert ar["annotations"][0]["name"] == "Call"
    # raw = PRE-resolve: no CodeQL grounding has happened yet
    assert ar["annotations"][0]["file"] is None
    assert ar["annotations"][0]["resolved_file"] is None


def test_path_in_scope_restricts_to_enclave_layer() -> None:
    """Subsystem scoping keeps a fork's own enclave paths and drops inherited code.

    suave-geth = go-ethereum + SUAVE: scope ``suave/`` must keep SUAVE's own code
    and drop inherited go-ethereum paths (accounts/, cmd/, node/). No scope = whole
    repo (backward compatible)."""
    assert path_in_scope("suave/core/config.go", ["suave/"]) is True
    assert path_in_scope("./suave/x.go", ["suave/"]) is True
    assert path_in_scope("accounts/keystore/passphrase.go", ["suave/"]) is False
    assert path_in_scope("cmd/devp2p/dnscmd.go", ["suave/"]) is False
    # No scope / empty scope = whole repo in scope (backward compatible).
    assert path_in_scope("anything.go", None) is True
    assert path_in_scope("anything.go", []) is True
    # Backslash / leading-slash normalization.
    assert path_in_scope("src\\verify.rs", ["src/"]) is True
    assert path_in_scope("/src/verify.rs", ["src/"]) is True


def test_classify_repo_applies_scope(monkeypatch, tmp_path: Path) -> None:
    """scope= restricts the enumerated items the LLM sees to in-scope paths."""
    from tee_audit.trustir.extractor import enumerate_classify as ec

    def fake_fetch(db, lang, codeql, work):
        return [
            EnumItem(kind="function", name="in_scope_fn", file="suave/core/x.go", line=1),
            EnumItem(kind="function", name="out_of_scope_fn", file="accounts/keystore/y.go", line=2),
        ]

    monkeypatch.setattr(ec, "run_fetch_queries", fake_fetch)
    payload = json.dumps([{"name": "in_scope_fn", "role": "host_input", "param": "p"}])
    client = FakeClient(payload)
    ann_set, index = classify_repo(
        repo_path=tmp_path / "r", language="go",
        codeql_path=Path("/usr/bin/codeql"), workdir=tmp_path / "w",
        db_path=tmp_path / "db", client=client, scope=["suave/"],
    )
    # Only the in-scope file's item reached the index; out-of-scope was dropped.
    names = {it.name for it in index.all_items()}
    assert "in_scope_fn" in names
    assert "out_of_scope_fn" not in names
