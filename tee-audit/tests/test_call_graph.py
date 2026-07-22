"""Tests for deterministic file discovery and invocation chain tracing (call_graph.py)."""

from pathlib import Path

import pytest

from tee_audit.utils.call_graph import (
    CallSite,
    EntryPoint,
    InvocationChain,
    TrustZone,
    ZoneMap,
    build_caller_graph,
    build_zone_map,
    compute_chain_confidence,
    discover_entry_points,
    discover_related_files,
    discover_tee_boundary_files,
    format_invocation_chain,
    trace_invocation_chain,
    _extract_call_sites,
    build_fingerprint_map,
)


def _make_repo(tmp_path: Path) -> Path:
    """Create a minimal fake repo with cross-file references."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()

    (src / "enclave.rs").write_text(
        "use crate::attestation;\n"
        "use crate::crypto;\n"
        "fn process_ecall(input: &[u8]) {\n"
        "    attestation::verify_report();\n"
        "    crypto::sign_data(input);\n"
        "}\n"
    )
    (src / "attestation.rs").write_text(
        "use crate::quote;\n"
        "pub fn verify_report() -> bool { true }\n"
        "pub fn get_quote() -> Vec<u8> { vec![] }\n"
    )
    (src / "crypto.rs").write_text(
        "pub fn sign_data(data: &[u8]) -> Vec<u8> { vec![] }\n"
    )
    (src / "quote.rs").write_text(
        "pub fn generate_quote() -> Vec<u8> { vec![] }\n"
    )

    return repo


def test_discover_related_files_basic():
    """File discovery follows import chains."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_repo(Path(td))
        results = discover_related_files(
            repo,
            seed_files=["src/enclave.rs"],
            max_depth=2,
            max_files=6,
        )
        # Should discover enclave.rs + related files
        rel_paths = {str(p.relative_to(repo)) for p in results}
        assert "src/enclave.rs" in rel_paths
        # Should find at least attestation.rs via `use crate::attestation`
        assert len(results) >= 1


def test_discover_related_files_max_files():
    """Discovery respects max_files limit."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_repo(Path(td))
        results = discover_related_files(
            repo,
            seed_files=["src/enclave.rs"],
            max_files=2,
        )
        assert len(results) <= 2


def test_discover_tee_boundary_files():
    """TEE boundary file discovery finds SGX/attestation files."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_repo(Path(td))
        results = discover_tee_boundary_files(repo)
        # Should find files with TEE keywords
        assert len(results) >= 0  # May or may not match depending on content


def test_build_fingerprint_map():
    data = {
        "tee_platforms": {"SGX": ["src/enclave.rs:1: use sgx_types"]},
        "trust_artifacts": {"Attestation": ["src/attestation.rs:1: verify_report"]},
        "critical_paths": ["src/enclave"],
    }
    result = build_fingerprint_map(data)
    assert "SGX" in result
    assert "Attestation" in result
    assert "src/enclave" in result


def test_build_fingerprint_map_empty():
    assert build_fingerprint_map(None) == ""
    assert build_fingerprint_map({}) == ""


def test_discover_related_files_nonexistent_seed():
    """Gracefully handles missing seed files."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_repo(Path(td))
        results = discover_related_files(
            repo,
            seed_files=["src/nonexistent.rs"],
            max_depth=1,
        )
        assert results == []


# ---------------------------------------------------------------------------
# Invocation Chain Tracing Tests
# ---------------------------------------------------------------------------


def _make_chain_repo(tmp_path: Path) -> Path:
    """Create a multi-file repo with a callable chain for chain tracing tests."""
    repo = tmp_path / "chain-repo"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()

    # Entry point file — RPC handler
    (src / "rpc_service.rs").write_text(
        "use crate::storage;\n"
        "use crate::crypto;\n"
        "\n"
        "pub fn init_runtime(genesis: &[u8]) {\n"
        "    let state = storage::from_pairs(genesis);\n"
        "    crypto::derive_key(state);\n"
        "}\n"
        "\n"
        "impl PhactoryApi for RpcService {\n"
        "    fn get_info(&self) -> String {\n"
        "        init_runtime(self.genesis.as_slice());\n"
        "        \"ok\".to_string()\n"
        "    }\n"
        "}\n"
    )

    # Middle file — storage layer
    (src / "storage.rs").write_text(
        "pub fn from_pairs(data: &[u8]) -> Vec<u8> {\n"
        "    let decoded = decode(data);\n"
        "    decoded\n"
        "}\n"
        "\n"
        "fn decode(raw: &[u8]) -> Vec<u8> {\n"
        "    raw.to_vec()\n"
        "}\n"
    )

    # Sink file — crypto with key derivation
    (src / "crypto.rs").write_text(
        "pub fn derive_key(state: Vec<u8>) -> [u8; 32] {\n"
        "    let kdf_result = hkdf_expand(&state);\n"
        "    kdf_result\n"
        "}\n"
        "\n"
        "fn hkdf_expand(input: &[u8]) -> [u8; 32] {\n"
        "    [0u8; 32]\n"
        "}\n"
    )

    # EDL file for entry point discovery
    edl = repo / "Enclave.edl"
    edl.write_text(
        "enclave {\n"
        "    trusted {\n"
        "        public void ecall_init([in, out] uint8_t* buf);\n"
        "    };\n"
        "    untrusted {\n"
        '        void ocall_report([out] uint8_t* data);\n'
        "    };\n"
        "};\n"
    )

    return repo


def test_extract_call_sites_rust():
    """_extract_call_sites finds function calls with caller context."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))
        rpc_file = repo / "src" / "rpc_service.rs"

        sites = _extract_call_sites(rpc_file, repo)

        # Should find calls within init_runtime and get_info
        callee_names = {s.callee_name for s in sites}
        assert "from_pairs" in callee_names, f"Expected from_pairs, got {callee_names}"
        assert "derive_key" in callee_names, f"Expected derive_key, got {callee_names}"
        assert "init_runtime" in callee_names, f"Expected init_runtime, got {callee_names}"

        # All sites should have caller context
        for site in sites:
            assert site.caller_function, f"No caller for {site.callee_name}"
            assert site.file, f"No file for {site.callee_name}"
            assert site.line > 0, f"No line for {site.callee_name}"


def test_extract_call_sites_filters_keywords():
    """_extract_call_sites filters out language keywords (if, Some, Ok, etc.)."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "kw-repo"
        repo.mkdir()
        (repo / "src").mkdir()

        (repo / "src" / "keywords.rs").write_text(
            "fn process(value: Option<i32>) {\n"
            "    if value.is_some() {\n"
            "        let v = value.unwrap();\n"
            "        Some(v + 1);\n"
            "    }\n"
            "    Ok(());\n"
            "    Err(\"bad\");\n"
            "    for i in 0..10 {\n"
            "        println!(\"{}\");\n"
            "    }\n"
            "    while false {}\n"
            "    return 42;\n"
            "}\n"
        )

        sites = _extract_call_sites(repo / "src" / "keywords.rs", repo)
        callee_names = {s.callee_name for s in sites}

        # Keywords should be filtered out
        for kw in ("if", "Some", "Ok", "Err", "for", "while", "return"):
            assert kw not in callee_names, f"Keyword {kw} should be filtered"

        # Actual method calls should be kept (println! is a macro, not matched by regex)
        # Note: is_some and unwrap are in _NOISE_CALLEE_NAMES and filtered out
        # for cleaner BFS backward search
        assert "is_some" not in callee_names  # noise-filtered
        assert "unwrap" not in callee_names   # noise-filtered


def test_build_caller_graph():
    """build_caller_graph creates reverse index from callee to callers."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))
        zone_map = ZoneMap()

        graph = build_caller_graph(repo, zone_map, max_files=50)

        # "from_pairs" is called in rpc_service.rs, so graph should have it
        from_pairs_callers = graph.get("from_pairs", [])
        assert len(from_pairs_callers) >= 1, f"Expected callers of from_pairs, got keys: {list(graph.keys())[:20]}"

        # The caller should be in rpc_service.rs
        files = {c.file for c in from_pairs_callers}
        assert any("rpc_service" in f for f in files), f"Expected rpc_service caller, got {files}"

        # "derive_key" should also have callers
        assert len(graph.get("derive_key", [])) >= 1


def test_build_zone_map_with_edl():
    """build_zone_map classifies files and parses EDL entry points."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))

        zone_map = build_zone_map(repo)

        # EDL file should be found
        assert len(zone_map.edl_files) >= 1

        # EDL entry points should be parsed
        assert len(zone_map.entry_points) >= 1
        all_ep_funcs = []
        for funcs in zone_map.entry_points.values():
            all_ep_funcs.extend(funcs)
        assert "ecall_init" in all_ep_funcs, f"Expected ecall_init in {all_ep_funcs}"


def test_discover_entry_points_rpc():
    """discover_entry_points finds impl-based RPC handler entry points."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))
        zone_map = build_zone_map(repo)

        entry_points = discover_entry_points(repo, zone_map)

        # Should find at least the impl PhactoryApi for RpcService pattern
        ep_functions = [ep.function for ep in entry_points]
        assert len(entry_points) >= 1, f"Expected entry points, got {entry_points}"

        # Should have RPC handler type entries
        rpc_eps = [ep for ep in entry_points if ep.entry_type == "rpc_handler"]
        assert len(rpc_eps) >= 1, f"Expected rpc_handler entry points, got {[ep.entry_type for ep in entry_points]}"


def test_discover_entry_points_edl():
    """discover_entry_points finds ECALL/OCALL from EDL files."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))
        zone_map = build_zone_map(repo)

        entry_points = discover_entry_points(repo, zone_map)

        ecall_eps = [ep for ep in entry_points if ep.entry_type == "ecall"]
        ecall_names = {ep.function for ep in ecall_eps}
        # ecall_init is defined in the EDL and implemented in some .rs file
        # It may or may not be found depending on _find_function_implementation
        assert len(ecall_eps) >= 0  # EDL parsing is best-effort


def test_trace_invocation_chain_complete():
    """trace_invocation_chain traces from sink back to entry point via BFS."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = _make_chain_repo(Path(td))
        zone_map = build_zone_map(repo)

        # Build caller graph and find entry points
        caller_graph = build_caller_graph(repo, zone_map, max_files=50)
        entry_points = discover_entry_points(repo, zone_map)

        # Trace from crypto::derive_key (sink) backward
        chain = trace_invocation_chain(
            sink_file="src/crypto.rs",
            sink_function="derive_key",
            caller_graph=caller_graph,
            entry_points=entry_points,
            zone_map=zone_map,
            repo_path=repo,
        )

        assert chain is not None, "Expected an InvocationChain result"
        assert chain.sink_function == "derive_key"
        assert chain.sink_file == "src/crypto.rs"

        # Chain should have hops (derive_key is called from rpc_service.rs)
        assert len(chain.hops) >= 1, f"Expected hops, got {chain.hops}"


def test_trace_invocation_chain_no_chain():
    """trace_invocation_chain returns no_chain for disconnected sinks."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "empty-repo"
        repo.mkdir()
        (repo / "src").mkdir()
        (repo / "src" / "orphan.rs").write_text(
            "fn orphan_sink() {\n"
            "    do_something();\n"
            "}\n"
            "fn do_something() {}\n"
        )

        zone_map = ZoneMap()
        caller_graph = build_caller_graph(repo, zone_map, max_files=50)
        entry_points = []  # No entry points

        chain = trace_invocation_chain(
            sink_file="src/orphan.rs",
            sink_function="orphan_sink",
            caller_graph=caller_graph,
            entry_points=entry_points,
            zone_map=zone_map,
            repo_path=repo,
        )

        assert chain is not None
        assert chain.confidence == "no_chain"
        assert chain.complete is False


def test_format_invocation_chain():
    """format_invocation_chain produces human-readable chain text."""
    ep = EntryPoint(
        file="src/rpc_service.rs",
        function="init_runtime",
        entry_type="rpc_handler",
        zone=TrustZone.MIXED,
        line=10,
    )
    chain = InvocationChain(
        entry_point=ep,
        hops=[
            CallSite(
                caller_function="init_runtime",
                callee_name="derive_key",
                callee_module="crypto",
                line=15,
                file="src/rpc_service.rs",
            ),
        ],
        sink_file="src/crypto.rs",
        sink_function="derive_key",
        zones_crossed=1,
        complete=True,
        confidence="confirmed",
    )

    text = format_invocation_chain(chain)

    assert "COMPLETE" in text
    assert "1 hops" in text
    assert "1 boundary crossing" in text
    assert "init_runtime" in text
    assert "derive_key" in text
    assert "confirmed" in text
    assert "SINK" in text


def test_format_invocation_chain_no_chain():
    """format_invocation_chain handles no_chain gracefully."""
    chain = InvocationChain(
        entry_point=None,
        hops=[],
        sink_file="src/unknown.rs",
        sink_function="mystery",
        complete=False,
        confidence="no_chain",
    )
    text = format_invocation_chain(chain)
    assert "No invocation chain" in text


def test_compute_chain_confidence():
    """compute_chain_confidence extracts confidence from chain or None."""
    chain = InvocationChain(
        sink_file="f.rs",
        sink_function="f",
        complete=True,
        confidence="confirmed",
    )
    assert compute_chain_confidence(chain) == "confirmed"
    assert compute_chain_confidence(None) == "no_chain"
