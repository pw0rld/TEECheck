"""SARIF 2.1.0 reporter for TrustIR findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# TrustIR status -> SARIF result level.
_LEVEL = {
    "confirmed": "error",
    "violated_candidate": "warning",
    "configuration_dependent": "warning",
    "delegated": "note",
    "guarded_elsewhere": "note",
    "test_only": "none",
    "out_of_scope": "none",
    "unresolved": "note",
}


def _level(status: str) -> str:
    return _LEVEL.get(status, "note")


def render_sarif(findings: list[dict[str, Any]], meta: dict[str, Any]) -> dict[str, Any]:
    # One rule per distinct TWE.
    rules = []
    seen: set[str] = set()
    for f in findings:
        twe = f.get("twe_id")
        if twe and twe not in seen:
            seen.add(twe)
            rules.append(
                {
                    "id": twe,
                    "name": twe.replace("-", "_").lower(),
                    "shortDescription": {"text": f.get("summary") or twe},
                }
            )

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.get("twe_id"),
                "level": _level(f.get("status", "unresolved")),
                "message": {
                    "text": (
                        f"[{f.get('status')}] {f.get('summary') or ''}"
                        + (f" — {f['note']}" if f.get("note") else "")
                    ).strip(),
                },
                "properties": {
                    "trustir_status": f.get("status"),
                    "family": f.get("family"),
                    "finding_id": f.get("finding_id"),
                    "authority_point_id": f.get("authority_point_id"),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tee-audit-trustir",
                        "informationUri": "https://github.com/pinshenxu/tee-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(sarif: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return out


__all__ = ["render_sarif", "write_sarif"]
