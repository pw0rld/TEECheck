"""JSON reporter for TrustIR findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def status_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


def render_report(findings: list[dict[str, Any]], meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "trustir-findings/v1",
        "repo": meta.get("repo"),
        "candidate": meta.get("candidate_id"),
        "twe_id": meta.get("twe_id"),
        "generated_at": meta.get("generated_at"),
        "finding_count": len(findings),
        "status_counts": status_counts(findings),
        "findings": findings,
    }


def write_report(report: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out


__all__ = ["render_report", "write_report", "status_counts"]
