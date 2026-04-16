"""Shared test fixtures."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant, InvariantFamily


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a minimal fake repo with TEE/Web3 signals."""
    repo = tmp_path / "fake-project"
    repo.mkdir()

    # Rust source with SGX signal
    src = repo / "src"
    src.mkdir()
    (src / "main.rs").write_text(
        'use sgx_types::*;\n'
        'fn main() { println!("hello"); }\n'
    )

    # Go source with Ethereum signal
    (src / "contract.go").write_text(
        'package main\n\nimport "github.com/ethereum/go-ethereum"\n'
    )

    # Enclave config
    (repo / "Enclave.config.xml").write_text("<Enclave><TL>3</TL></Enclave>")

    # Cargo.toml for build detection
    (repo / "Cargo.toml").write_text('[package]\nname = "test"\n')

    # Attestation module
    att = src / "attestation.rs"
    att.write_text("fn verify_report() -> bool { true }\n")

    # .git directory so commit hash detection works
    git_dir = repo / ".git"
    git_dir.mkdir()

    return repo


@pytest.fixture
def sample_fingerprint() -> Fingerprint:
    """A sample Fingerprint for testing."""
    return Fingerprint(
        repo_root="/tmp/test-repo",
        top_extensions={"rs": 42, "go": 15, "toml": 3},
        codeql_languages=["go", "rust"],
        tee_platforms={"SGX": ["src/enclave.rs:1: use sgx_types::*;"]},
        web3_roles={"Ethereum": ["src/contract.go:3: ethereum"]},
        trust_artifacts={"Attestation": ["src/attestation.rs:1: verify_report"]},
        build_flags={},
        critical_paths=["src/enclave"],
    )


@pytest.fixture
def sample_invariants() -> list[Invariant]:
    """Sample invariants for testing."""
    return [
        Invariant(
            id="INV-01",
            description="All enclave inputs must be validated before use",
            trust_path="host → enclave",
            family=InvariantFamily.GUARD,
            sources=["host_input"],
            sinks=["enclave_handler"],
            guards=["input_validator"],
            failure_modes=["unvalidated input reaches enclave"],
            codeql_expressible=True,
        ),
        Invariant(
            id="INV-02",
            description="Attestation report must bind to unique session",
            trust_path="enclave → verifier",
            family=InvariantFamily.BINDING,
            sources=["enclave_report"],
            sinks=["verifier_check"],
            guards=["report_binder"],
            failure_modes=["report replay"],
            codeql_expressible=True,
        ),
        Invariant(
            id="INV-03",
            description="Private key never leaves enclave boundary",
            trust_path="key_manager → enclave",
            family=InvariantFamily.FLOW,
            sources=["key_storage"],
            sinks=["enclave_api"],
            guards=["boundary_check"],
            failure_modes=["key exfiltration"],
            codeql_expressible=False,
        ),
    ]


@pytest.fixture
def sample_sarif(tmp_path: Path) -> Path:
    """Create a minimal SARIF 2.1.0 file for testing."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tee-audit-codeql",
                        "rules": []
                    }
                },
                "results": [
                    {
                        "ruleId": "inv-01-guard/input-validation",
                        "message": {"text": "Potential missing input validation"},
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/main.rs"},
                                    "region": {"startLine": 10, "startColumn": 5}
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "inv-02-binding/attestation-binding",
                        "message": {"text": "Attestation report may not be session-bound"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/attestation.rs"},
                                    "region": {"startLine": 42}
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "custom-guard-check",
                        "message": {"text": "Guard verified complete: input validation present"},
                        "level": "note",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/guard.rs"},
                                    "region": {"startLine": 15}
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "inv-03-flow/key-boundary",
                        "message": {"text": "Key boundary check info: no exfiltration path found"},
                        "level": "note",
                        "locations": []
                    }
                ]
            }
        ]
    }
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(sarif, indent=2))
    return path
