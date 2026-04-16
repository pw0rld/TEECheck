"""Tests for Stage 3: Analysis Matrix."""

from __future__ import annotations

from tee_audit.stages.matrix import generate_matrix_tsv, render_markdown_table, run_matrix
from tee_audit.contracts import Stage3Input
from tee_audit.models.invariant import InvariantFamily


class TestGenerateTsv:
    def test_header_and_rows(self, sample_invariants):
        tsv = generate_matrix_tsv(sample_invariants)
        lines = tsv.strip().splitlines()
        assert len(lines) == 4  # header + 3 invariants
        assert "invariant_id" in lines[0]
        assert "INV-01" in lines[1]

    def test_codeql_expressible_flag(self, sample_invariants):
        tsv = generate_matrix_tsv(sample_invariants)
        lines = tsv.strip().splitlines()
        # INV-01 and INV-02 are codeql_expressible=True, INV-03 is False
        parts_01 = lines[1].split("\t")
        parts_03 = lines[3].split("\t")
        assert parts_01[3] == "CodeQL"
        assert parts_03[3] == "Manual"

    def test_six_columns(self, sample_invariants):
        tsv = generate_matrix_tsv(sample_invariants)
        for line in tsv.strip().splitlines():
            assert len(line.split("\t")) == 6

    def test_empty_invariants(self):
        tsv = generate_matrix_tsv([])
        lines = tsv.strip().splitlines()
        assert len(lines) == 1  # header only


class TestRenderMarkdown:
    def test_produces_table(self, sample_invariants):
        tsv = generate_matrix_tsv(sample_invariants)
        md = render_markdown_table(tsv)
        assert md.startswith("|")
        assert "---" in md

    def test_row_count(self, sample_invariants):
        tsv = generate_matrix_tsv(sample_invariants)
        md = render_markdown_table(tsv)
        lines = [l for l in md.splitlines() if l.startswith("|")]
        # header + separator + 3 data rows = 5
        assert len(lines) == 5

    def test_pipe_escaping(self):
        tsv = "col1\tcol2\tcol3\tcol4\tcol5\tcol6"
        md = render_markdown_table(tsv)
        assert "| col1 |" in md

    def test_empty_tsv(self):
        assert render_markdown_table("") == ""


class TestRunMatrix:
    def test_full_run(self, sample_invariants):
        inp = Stage3Input(invariants=sample_invariants)
        out = run_matrix(inp)
        assert "# Analysis family matrix" in out.matrix_markdown
        assert "INV-01" in out.matrix_tsv
        assert "INV-02" in out.matrix_tsv
