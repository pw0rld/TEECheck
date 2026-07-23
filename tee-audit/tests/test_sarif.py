"""Tests for SARIF parsing utilities."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tee_audit.utils.sarif import parse_sarif, extract_results


class TestParseSarif:
    def test_parses_valid_sarif(self, sample_sarif: Path):
        doc = parse_sarif(sample_sarif)
        assert doc.schema_version  # schema field present
        assert len(doc.runs) == 1
        assert doc.runs[0].tool_name == "tee-audit-codeql"

    def test_extracts_results(self, sample_sarif: Path):
        doc = parse_sarif(sample_sarif)
        results = extract_results(doc)
        assert len(results) == 4
        assert results[0].rule_id == "inv-01-guard/input-validation"

    def test_locations_parsed(self, sample_sarif: Path):
        doc = parse_sarif(sample_sarif)
        results = extract_results(doc)
        first = results[0]
        assert len(first.locations) == 1
        assert first.locations[0].file == "src/main.rs"
        assert first.locations[0].line == 10

    def test_empty_locations(self, sample_sarif: Path):
        doc = parse_sarif(sample_sarif)
        results = extract_results(doc)
        # Last result has empty locations
        assert results[3].locations == []

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_sarif(tmp_path / "nonexistent.sarif")

    def test_multi_run(self, tmp_path: Path):
        sarif = {
            "$schema": "https://sarif-2.1.0.schema",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "tool-a"}},
                    "results": [
                        {"ruleId": "r1", "message": {"text": "msg1"}, "locations": []}
                    ],
                },
                {
                    "tool": {"driver": {"name": "tool-b"}},
                    "results": [
                        {"ruleId": "r2", "message": {"text": "msg2"}, "locations": []}
                    ],
                },
            ],
        }
        path = tmp_path / "multi.sarif"
        path.write_text(json.dumps(sarif))
        doc = parse_sarif(path)
        assert len(doc.runs) == 2
        all_results = extract_results(doc)
        assert len(all_results) == 2

    def test_severity_extracted(self, sample_sarif: Path):
        doc = parse_sarif(sample_sarif)
        results = extract_results(doc)
        assert results[0].severity == "warning"
        assert results[1].severity == "error"
