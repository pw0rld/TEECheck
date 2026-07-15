"""CLI integration tests for the `tee-audit trustir` subcommand."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from tee_audit.cli import main


def _init_git(repo: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"],
        cwd=repo, check=True,
    )


def _fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "fixrepo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.go").write_text(
        "package main\n\nfunc doAction() {\n\t// authority point\n}\n", encoding="utf-8"
    )
    _init_git(repo)
    return repo


def _annotations(path: Path) -> Path:
    """A minimal TrustAnnotationSet (one authority point) for the deterministic path."""
    ann = {
        "repo": "fixrepo",
        "language": "go",
        "annotations": [
            {"id": "auth-1", "kind": "authority", "role": "key_release",
             "name": "doAction", "file": "src/x.go", "line": 3},
        ],
    }
    path.write_text(json.dumps(ann), encoding="utf-8")
    return path


def test_trustir_help() -> None:
    result = CliRunner().invoke(main, ["trustir", "--help"])
    assert result.exit_code == 0, result.output
    assert "TrustIR" in result.output
    assert "--annotations" in result.output
    assert "--no-codeql" in result.output


def test_trustir_no_codeql_annotations_run(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    ann = _annotations(tmp_path / "ann.json")
    out_root = tmp_path / "out"

    result = CliRunner().invoke(
        main,
        ["trustir", "--repo", str(repo), "--annotations", str(ann),
         "--no-codeql", "--twe", "TWE-BIND-001", "--output-dir", str(out_root)],
    )
    assert result.exit_code == 0, result.output

    # New layout: <out>/<name>-audit/trustir/results/findings.json
    findings_path = out_root / "fixrepo-audit" / "trustir" / "results" / "findings.json"
    assert findings_path.exists(), result.output
    data = json.loads(findings_path.read_text())
    # Without CodeQL there are no query results -> 0 findings.
    assert data["finding_count"] == 0
    assert (findings_path.parent / "findings.md").exists()
    assert (findings_path.parent / "findings.sarif").exists()
