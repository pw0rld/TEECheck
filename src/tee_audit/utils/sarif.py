"""SARIF parsing utilities."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SarifLocation(BaseModel):
    """A location within a SARIF result."""

    file: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None


class SarifCodeFlowLocation(BaseModel):
    """A single location in a SARIF code flow (data flow path)."""

    file: str
    line: int | None = None
    message: str = ""


class SarifCodeFlow(BaseModel):
    """A code flow (data flow path) from a SARIF path-problem result."""

    locations: list[SarifCodeFlowLocation]


class SarifResult(BaseModel):
    """A single result from a SARIF run."""

    rule_id: str
    message: str
    locations: list[SarifLocation]
    severity: str | None = None
    confidence: str | None = None
    code_flows: list[SarifCodeFlow] = []


class SarifRun(BaseModel):
    """A single run within a SARIF document."""

    tool_name: str
    results: list[SarifResult]


class SarifDocument(BaseModel):
    """A parsed SARIF 2.1.0 document."""

    schema_version: str
    runs: list[SarifRun]


def parse_sarif(path: Path) -> SarifDocument:
    """Parse a SARIF 2.1.0 file into a structured model.

    Validates the schema version and extracts key fields.
    """
    if not path.exists():
        msg = f"SARIF file not found: {path}"
        raise FileNotFoundError(msg)

    raw = json.loads(path.read_text())

    version = raw.get("$schema", "")
    if "sarif-2.1.0" not in version and raw.get("version") != "2.1.0":
        logger.warning("Unexpected SARIF schema version: %s", version)

    runs: list[SarifRun] = []
    for run in raw.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "unknown")

        results: list[SarifResult] = []
        for r in run.get("results", []):
            locations: list[SarifLocation] = []
            for loc in r.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                locations.append(SarifLocation(
                    file=artifact.get("uri", "unknown"),
                    line=region.get("startLine"),
                    column=region.get("startColumn"),
                    snippet=region.get("snippet", {}).get("text") if isinstance(region.get("snippet"), dict) else None,
                ))

            results.append(SarifResult(
                rule_id=r.get("ruleId", "unknown"),
                message=r.get("message", {}).get("text", ""),
                locations=locations,
                severity=r.get("level"),
                confidence=None,
                code_flows=_parse_code_flows(r),
            ))

        runs.append(SarifRun(tool_name=tool_name, results=results))

    return SarifDocument(schema_version=version, runs=runs)


def extract_results(doc: SarifDocument) -> list[SarifResult]:
    """Extract all results from a SARIF document across all runs."""
    return [r for run in doc.runs for r in run.results]


def _parse_code_flows(result: dict) -> list[SarifCodeFlow]:
    """Extract code flows (data flow paths) from a SARIF result."""
    flows: list[SarifCodeFlow] = []
    for cf in result.get("codeFlows", []):
        locations: list[SarifCodeFlowLocation] = []
        for tf in cf.get("threadFlows", []):
            for loc in tf.get("locations", []):
                loc_data = loc.get("location", {})
                phys = loc_data.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                msg = loc_data.get("message", {}).get("text", "")
                locations.append(SarifCodeFlowLocation(
                    file=artifact.get("uri", "unknown"),
                    line=region.get("startLine"),
                    message=msg,
                ))
        if locations:
            flows.append(SarifCodeFlow(locations=locations))
    return flows


def extract_code_flows_by_rule(doc: SarifDocument) -> dict[str, list[SarifCodeFlow]]:
    """Extract code flows grouped by rule ID from a SARIF document.

    Returns {rule_id: [code_flows]} for results that have code flows.
    """
    by_rule: dict[str, list[SarifCodeFlow]] = {}
    for result in extract_results(doc):
        if result.code_flows:
            by_rule.setdefault(result.rule_id, []).extend(result.code_flows)
    return by_rule
