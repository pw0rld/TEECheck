"""Tests for TrustIR reporters (US-008 part A)."""

from __future__ import annotations

import json
from pathlib import Path

from tee_audit.trustir.reporter import render_json, render_md, render_sarif, write_json, write_md, write_sarif


def _findings() -> list[dict]:
    return [
        {
            "finding_id": "F1", "candidate_id": "C1", "twe_id": "TWE-BIND-001",
            "family": "Binding", "authority_point_id": "AP1", "status": "confirmed",
            "summary": "Registered agent not bound to attested key.",
            "suppressors_checked": {"test_only": False}, "coverage_limits": [], "note": "",
        },
        {
            "finding_id": "F2", "candidate_id": "C1", "twe_id": "TWE-DESIGN-001",
            "family": "Design", "authority_point_id": "AP2", "status": "violated_candidate",
            "summary": "Possible bypass.", "suppressors_checked": {}, "coverage_limits": ["manual"], "note": "manual_review_required:Design",
        },
    ]


def _meta() -> dict:
    return {"repo": "example", "candidate_id": "C1", "twe_id": "TWE-BIND-001", "generated_at": "2026-07-02"}


def test_json_report_structure() -> None:
    report = render_json(_findings(), _meta())
    assert report["schema"] == "trustir-findings/v1"
    assert report["finding_count"] == 2
    assert report["status_counts"]["confirmed"] == 1
    assert report["status_counts"]["violated_candidate"] == 1
    assert len(report["findings"]) == 2


def test_json_report_write(tmp_path: Path) -> None:
    report = render_json(_findings(), _meta())
    p = write_json(report, tmp_path / "out" / "findings.json")
    assert p.exists()
    loaded = json.loads(p.read_text())
    assert loaded["finding_count"] == 2


def test_markdown_contains_status_summary_and_findings() -> None:
    md = render_md(_findings(), _meta())
    assert "# TrustIR Findings — example" in md
    assert "Status summary" in md
    assert "`confirmed`" in md
    assert "TWE-BIND-001" in md
    assert "manual_review_required:Design" in md


def test_markdown_empty_findings() -> None:
    md = render_md([], _meta())
    assert "Total findings: **0**" in md
    assert "_No findings._" in md


def test_markdown_write(tmp_path: Path) -> None:
    p = write_md(render_md(_findings(), _meta()), tmp_path / "x" / "findings.md")
    assert p.exists() and p.read_text().startswith("# TrustIR")


def test_sarif_structure_and_levels() -> None:
    sarif = render_sarif(_findings(), _meta())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "tee-audit-trustir"
    # one rule per distinct TWE (2 distinct here)
    assert len(run["tool"]["driver"]["rules"]) == 2
    results = run["results"]
    assert len(results) == 2
    levels = {r["properties"]["trustir_status"]: r["level"] for r in results}
    assert levels["confirmed"] == "error"
    assert levels["violated_candidate"] == "warning"


def test_sarif_write(tmp_path: Path) -> None:
    p = write_sarif(render_sarif(_findings(), _meta()), tmp_path / "y" / "findings.sarif")
    loaded = json.loads(p.read_text())
    assert loaded["version"] == "2.1.0"
