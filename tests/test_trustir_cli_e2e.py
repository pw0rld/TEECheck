"""End-to-end pipeline via CLI with --annotations (deterministic, no LLM).

Proves the full flow on a real Go DB: annotations -> resolve -> one facts
module -> run all queries -> solve -> findings WITH a concrete source->sink path.
Requires CodeQL + Go; skips otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from tee_audit.cli import main

_FIXTURE_GO = """package main

func verifyQuote() string { return "attested" }

func registerAgent(agentAddr string) { _ = agentAddr }

func handle(input string) {
\tkey := verifyQuote()
\tregisterAgent("0xabc")
\tderiveKey(input)
\t_ = key
}

func deriveKey(seed string) {}
"""

_ANNOTATIONS = {
    "repo": "fixrepo",
    "language": "go",
    "annotations": [
        {"id": "V", "kind": "verifier", "role": "attestation_verifier",
         "name": "verifyQuote", "file": "main.go", "line": 3, "claim_field_role": "attested_public_key"},
        {"id": "A", "kind": "authority", "role": "registration_acceptance",
         "name": "registerAgent", "file": "main.go", "line": 5,
         "subject_param": "agentAddr", "subject_role": "registered_agent"},
        {"id": "S", "kind": "source", "role": "host_input",
         "name": "handle", "param": "input", "file": "main.go", "line": 7},
        {"id": "K", "kind": "sink", "role": "key_derivation_input",
         "name": "deriveKey", "file": "main.go", "line": 11},
    ],
}


def _ready() -> bool:
    try:
        from tee_audit.utils.codeql_check import find_codeql

        return bool(find_codeql()) and (
            shutil.which("go") or (Path.home() / "opt" / "go" / "bin" / "go").exists()
        )
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="CodeQL CLI or Go toolchain not available")


def _init_git(repo: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"],
        cwd=repo, check=True,
    )


def test_pipeline_deterministic_end_to_end(tmp_path: Path) -> None:
    repo = tmp_path / "fixrepo"
    repo.mkdir(parents=True)
    (repo / "main.go").write_text(_FIXTURE_GO, encoding="utf-8")
    _init_git(repo)
    ann = tmp_path / "ann.json"
    ann.write_text(json.dumps(_ANNOTATIONS), encoding="utf-8")
    out_root = tmp_path / "out"

    result = CliRunner().invoke(
        main,
        ["trustir", "--repo", str(repo), "--annotations", str(ann),
         "--language", "go", "--output-dir", str(out_root)],
    )
    assert result.exit_code == 0, result.output

    # Layout: <out>/<name>-audit/trustir/results/findings.json
    findings_path = out_root / "fixrepo-audit" / "trustir" / "results" / "findings.json"
    assert findings_path.exists(), result.output
    data = json.loads(findings_path.read_text())
    assert data["finding_count"] >= 1, "should produce >=1 finding from a real path"
    twe_ids = {f["twe_id"] for f in data["findings"]}
    assert "TWE-BIND-001" in twe_ids
    # at least one finding carries a concrete source->sink path
    with_path = [f for f in data["findings"] if f.get("path")]
    assert with_path, "at least one finding should include a source->sink path"
    # resolved + rejected artifacts persisted
    assert (findings_path.parent / "annotations.resolved.json").exists()
    assert (findings_path.parent / "rejected.json").exists()
