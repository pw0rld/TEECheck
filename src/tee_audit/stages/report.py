"""Stage 6: Report Assembly — build final audit report."""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage6Input, Stage6Output
from tee_audit.llm.client import LLMClient
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.finding import Severity, TrustPathTier
from tee_audit.models.report import DashboardEntry, Report

logger = logging.getLogger(__name__)


class ReportResponse(BaseModel):
    """Wrapper for LLM report narrative response."""

    executive_summary: str
    methodology_notes: str


def _build_dashboard(findings: list) -> list[DashboardEntry]:
    """Build severity × trust-path-tier dashboard matrix deterministically."""
    counts: Counter[tuple[str, str]] = Counter()
    for f in findings:
        counts[(f.severity.value, f.trust_path_tier.value)] += 1

    entries = []
    for severity in Severity:
        for tier in TrustPathTier:
            count = counts.get((severity.value, tier.value), 0)
            if count > 0:
                entries.append(DashboardEntry(severity=severity, trust_path_tier=tier, count=count))
    return entries


def _render_markdown_report(report: Report) -> str:
    """Render the report as a Markdown document."""
    lines: list[str] = []

    lines.append(f"# TEE Security Audit Report: {report.project_name}")
    lines.append("")

    # Executive Summary
    if report.executive_summary:
        lines.append("## Executive Summary")
        lines.append(report.executive_summary)
        lines.append("")

    # Dashboard
    if report.dashboard:
        lines.append("## Dashboard Summary")
        lines.append("")
        lines.append("| Severity | Trust-Path Tier | Count |")
        lines.append("| --- | --- | --- |")
        for entry in report.dashboard:
            lines.append(f"| {entry.severity.value} | {entry.trust_path_tier.value} | {entry.count} |")
        lines.append("")

    # Findings
    if report.findings:
        lines.append("## Verified Findings")
        lines.append("")
        for f in report.findings:
            lines.append(f"### {f.id}: {f.title}")
            lines.append(f"- **Severity**: {f.severity.value}")
            lines.append(f"- **Confidence**: {f.confidence.value}")
            lines.append(f"- **Invariant**: {f.invariant_id}")
            lines.append(f"- **Trust-Path Tier**: {f.trust_path_tier.value}")
            lines.append("")
            lines.append("**Attack Path (POC):**")
            for step in f.attack_path:
                lines.append(f"  {step}")
            lines.append("")
            if f.code_locations:
                lines.append("**Code Locations:**")
                for loc in f.code_locations:
                    lines.append(f"  - {loc.file}:{loc.line}")
                lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")

    # Positive Guards
    if report.positive_guards:
        lines.append("## Positive Guards")
        lines.append("")
        for pg in report.positive_guards:
            lines.append(f"### {pg.id}: {pg.description[:100]}")
            lines.append(f"- **Invariants**: {', '.join(pg.invariant_refs)}")
            lines.append(f"- **Completeness**: {pg.completeness_status}")
            lines.append(f"- **Evidence**: {pg.code_evidence}")
            lines.append("")

    # Unknowns
    if report.unknowns:
        lines.append("## Agent-Validated Unknowns")
        lines.append("")
        for u in report.unknowns:
            lines.append(f"### {u.id}: {u.what_was_checked[:100]}")
            lines.append(f"- **Why Uncertain**: {u.why_uncertain}")
            lines.append(f"- **Recommended Steps**: {', '.join(u.recommended_steps)}")
            lines.append("")

    return "\n".join(lines)


def run_report(
    input_data: Stage6Input,
    client: LLMClient,
    results_dir: Path,
) -> Stage6Output:
    """Run Stage 6: Assemble final audit report."""
    logger.info("Stage 6: Assembling report")

    # Build dashboard deterministically
    dashboard = _build_dashboard(input_data.findings)

    # Generate executive summary via LLM
    findings_summary = json.dumps(
        [{"id": f.id, "title": f.title, "severity": f.severity.value} for f in input_data.findings],
        indent=2,
    )

    try:
        response = parse_with_retry(
            client,
            "You are a security auditor writing an executive summary for a TEE audit report.",
            f"Write a concise executive summary for these findings:\n{findings_summary}",
            ReportResponse,
            error_save_dir=results_dir,
        )
        executive_summary = response.executive_summary
    except Exception as e:
        logger.warning("LLM report generation failed, using fallback summary: %s", str(e)[:200])
        executive_summary = f"Audit found {len(input_data.findings)} findings across {len(set(f.invariant_id for f in input_data.findings))} invariants."

    # Assemble report
    report = Report(
        project_name=input_data.fingerprint.repo_root.split("/")[-1] if input_data.fingerprint else "unknown",
        fingerprint=input_data.fingerprint,
        invariants=input_data.invariants,
        findings=input_data.findings,
        positive_guards=input_data.positive_guards,
        unknowns=input_data.unknowns,
        dashboard=dashboard,
        executive_summary=executive_summary,
    )

    # Write Markdown report
    results_dir.mkdir(parents=True, exist_ok=True)
    report_path = results_dir / "report.md"
    markdown = _render_markdown_report(report)
    report_path.write_text(markdown)

    # Write JSON report for programmatic consumption
    json_path = results_dir / "report.json"
    json_path.write_text(report.model_dump_json(indent=2))

    logger.info("Stage 6 complete: report written to %s", report_path)
    return Stage6Output(report=report, report_path=report_path)
