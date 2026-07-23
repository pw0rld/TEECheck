"""Tests for per-stage typed contracts."""

from __future__ import annotations

from pathlib import Path

from tee_audit.contracts import (
    Stage0Output,
    Stage1Input,
    Stage1Output,
    Stage2Input,
    Stage2Output,
    Stage3Input,
    Stage3Output,
    Stage4Input,
    Stage4Output,
    Stage5aInput,
    Stage5aOutput,
    Stage5bInput,
    Stage5bOutput,
    Stage6Input,
    Stage6Output,
)
from tee_audit.models.invariant import InvariantFamily


class TestStage0:
    def test_output_round_trip(self, sample_fingerprint):
        out = Stage0Output(fingerprint=sample_fingerprint)
        data = out.model_dump()
        restored = Stage0Output.model_validate(data)
        assert restored.fingerprint.repo_root == sample_fingerprint.repo_root


class TestStage1:
    def test_input_requires_path(self, sample_fingerprint):
        inp = Stage1Input(repo_path=Path("/tmp/repo"), fingerprint=sample_fingerprint)
        assert inp.repo_path == Path("/tmp/repo")

    def test_output_structure(self):
        out = Stage1Output(dossier="full text", sections={"arch": "details"})
        assert out.sections["arch"] == "details"


class TestStage2:
    def test_input(self, sample_fingerprint):
        inp = Stage2Input(fingerprint=sample_fingerprint, dossier="dossier text")
        assert inp.dossier == "dossier text"

    def test_output(self, sample_invariants):
        out = Stage2Output(invariants=sample_invariants)
        assert len(out.invariants) == 3


class TestStage3:
    def test_input(self, sample_invariants):
        inp = Stage3Input(invariants=sample_invariants)
        assert len(inp.invariants) == 3

    def test_output(self):
        out = Stage3Output(matrix_markdown="# Table\n| a |", matrix_tsv="a\tb")
        assert "Table" in out.matrix_markdown


class TestStage4:
    def test_input(self, sample_invariants):
        inp = Stage4Input(repo_path=Path("/tmp/repo"), invariants=sample_invariants)
        assert inp.repo_path == Path("/tmp/repo")

    def test_output(self):
        out = Stage4Output(db_path=Path("/tmp/db"), sarif_path=Path("/tmp/res.sarif"), result_count=5)
        assert out.result_count == 5


class TestStage5a:
    def test_input(self, sample_sarif, sample_invariants):
        inp = Stage5aInput(sarif_path=sample_sarif, invariants=sample_invariants)
        assert inp.sarif_path == sample_sarif


class TestStage5b:
    def test_input(self, sample_invariants):
        inp = Stage5bInput(
            graded_findings=[],
            invariants=sample_invariants,
            repo_path=Path("/tmp/repo"),
        )
        assert len(inp.invariants) == 3

    def test_output(self):
        out = Stage5bOutput(verified_findings=[], unknowns=[])
        assert out.verified_findings == []


class TestStage6:
    def test_input(self, sample_fingerprint, sample_invariants):
        inp = Stage6Input(
            fingerprint=sample_fingerprint,
            invariants=sample_invariants,
            findings=[],
            positive_guards=[],
            unknowns=[],
        )
        assert inp.fingerprint.repo_root == "/tmp/test-repo"
