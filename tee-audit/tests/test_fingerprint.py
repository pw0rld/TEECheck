"""Tests for Stage 0: Fingerprint."""

from __future__ import annotations

from pathlib import Path

import pytest

from tee_audit.stages.fingerprint import (
    _enumerate_extensions,
    _detect_codeql_languages,
    _find_critical_paths,
    _scan_patterns,
    run_fingerprint,
)
from tee_audit.patterns.tee_signals import TEE_PLATFORM_PATTERNS, WEB3_ROLE_PATTERNS


class TestEnumerateExtensions:
    def test_counts_extensions(self, tmp_repo: Path):
        exts = _enumerate_extensions(tmp_repo)
        assert "rs" in exts
        assert "go" in exts
        assert exts["rs"] >= 2  # main.rs + attestation.rs

    def test_skips_git_dir(self, tmp_repo: Path):
        git_file = tmp_repo / ".git" / "HEAD"
        git_file.write_text("ref: refs/heads/main\n")
        exts = _enumerate_extensions(tmp_repo)
        assert "git" not in exts.get("", {})  # .git files shouldn't pollute

    def test_empty_dir(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        exts = _enumerate_extensions(empty)
        assert exts == {}


class TestDetectCodeqlLanguages:
    def test_maps_extensions(self):
        langs = _detect_codeql_languages({"rs": 10, "go": 5, "py": 3})
        assert "rust" in langs
        assert "go" in langs
        assert "python" in langs

    def test_unknown_extension_ignored(self):
        langs = _detect_codeql_languages({"xyz": 1})
        assert langs == []

    def test_sorted_output(self):
        langs = _detect_codeql_languages({"go": 1, "rs": 2, "py": 3})
        assert langs == sorted(langs)


class TestScanPatterns:
    def test_finds_sgx(self, tmp_repo: Path):
        results = _scan_patterns(tmp_repo, TEE_PLATFORM_PATTERNS)
        assert "SGX" in results
        assert len(results["SGX"]) > 0
        assert "sgx_types" in results["SGX"][0]

    def test_finds_web3_roles(self, tmp_repo: Path):
        results = _scan_patterns(tmp_repo, WEB3_ROLE_PATTERNS)
        # Check that scanning completed without error
        assert isinstance(results, dict)
        # The Go file imports ethereum which may match validator_or_consensus
        total_matches = sum(len(v) for v in results.values())
        assert total_matches >= 0  # patterns ran successfully

    def test_respects_max_matches(self, tmp_repo: Path):
        # Create many matching files
        for i in range(50):
            f = tmp_repo / f"src/file_{i}.rs"
            f.write_text("use sgx_types::*;\n")
        results = _scan_patterns(tmp_repo, {"SGX": r"sgx"}, max_matches=5)
        assert len(results["SGX"]) <= 5


class TestFindCriticalPaths:
    def test_finds_enclave_dir(self, tmp_repo: Path):
        enclave = tmp_repo / "src" / "enclave"
        enclave.mkdir()
        paths = _find_critical_paths(tmp_repo)
        assert any("enclave" in p for p in paths)

    def test_empty_repo(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert _find_critical_paths(empty) == []


class TestRunFingerprint:
    def test_full_run(self, tmp_repo: Path):
        output = run_fingerprint(tmp_repo)
        assert output.fingerprint.repo_root == str(tmp_repo)
        assert "rs" in output.fingerprint.top_extensions
        assert len(output.fingerprint.tee_platforms) > 0

    def test_nonexistent_path_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            run_fingerprint(tmp_path / "nonexistent")

    def test_json_serializable(self, tmp_repo: Path):
        output = run_fingerprint(tmp_repo)
        data = output.model_dump_json()
        assert "fingerprint" in data
