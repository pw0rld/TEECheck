"""Stage 5b: Deep Verification — LLM-powered finding verification.

Expanded into sub-phases reflecting the complexity of deep-verification.md:
5b.1: SARIF clustering
5b.2: Code context assembly
5b.3: Per-cluster LLM verification (parallel)
5b.4: Self-validation loop
5b.5: Severity assignment
5b.6: Output assembly
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage5bInput, Stage5bOutput
from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.finding import Finding, Severity, Confidence, TrustPathTier, CodeLocation
from tee_audit.models.triage import GradedFinding
from tee_audit.models.unknown import Unknown

logger = logging.getLogger(__name__)


class FindingResponse(BaseModel):
    """Wrapper for a single LLM-verified finding."""

    finding: Finding | None = None
    is_unknown: bool = False
    unknown_description: str = ""


class FindingsBatchResponse(BaseModel):
    """Wrapper for a batch of findings from one cluster."""

    findings: list[Finding]
    unknowns: list[Unknown]


# --- Sub-phase 5b.1: Clustering ---

def _cluster_by_invariant_and_file(
    graded_findings: list[GradedFinding],
) -> dict[str, list[GradedFinding]]:
    """Cluster graded findings by (invariant_id, file) pairs."""
    clusters: dict[str, list[GradedFinding]] = defaultdict(list)
    for gf in graded_findings:
        file_path = gf.code_location.split(":")[0] if ":" in gf.code_location else gf.code_location
        key = f"{gf.invariant_id}::{file_path}"
        clusters[key].append(gf)
    return dict(clusters)


# --- Sub-phase 5b.2: Code context assembly ---

def _read_code_context(file_path: Path, line: int | None, context_lines: int = 50) -> str:
    """Read source code around a location with context window."""
    if not file_path.exists():
        return f"[File not found: {file_path}]"

    try:
        lines = file_path.read_text(errors="ignore").splitlines()
        if line is None:
            # Return first N lines
            return "\n".join(lines[:context_lines * 2])

        start = max(0, line - context_lines)
        end = min(len(lines), line + context_lines)
        return "\n".join(
            f"{i + 1:4d} | {lines[i]}"
            for i in range(start, end)
        )
    except (OSError, ValueError) as e:
        return f"[Error reading {file_path}: {e}]"


# --- Sub-phase 5b.3: Per-cluster LLM verification ---

def _verify_cluster(
    cluster_key: str,
    findings: list[GradedFinding],
    repo_path: Path,
    client: LLMClient,
) -> tuple[list[Finding], list[Unknown]]:
    """Verify a single finding cluster via LLM."""
    # Assemble code context for the cluster
    code_contexts: list[str] = []
    for gf in findings:
        parts = gf.code_location.split(":")
        file_name = parts[0] if parts else ""
        line_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        file_path = repo_path / file_name
        context = _read_code_context(file_path, line_num)
        code_contexts.append(f"### {gf.code_location}\n```\n{context}\n```")

    code_text = "\n\n".join(code_contexts)
    if len(code_text) > 8000:
        code_text = code_text[:8000] + "\n...[truncated]"

    findings_summary = "\n".join(
        f"- {gf.sarif_result_id}: {gf.message} (grade: {gf.grade})" for gf in findings
    )

    prompt = load_prompt(
        "deep_verify",
        code_context=code_text,
        findings_summary=findings_summary,
        cluster_id=cluster_key,
    )

    system_prompt = (
        "You are a security researcher performing deep verification of static analysis findings "
        "in a TEE-enabled Web3 project. For each finding cluster: verify the attack path is real, "
        "assign severity (Critical/High/Medium/Low/Info), verify confidence, and write a POC. "
        "If a finding cannot be verified, mark it as an unknown."
    )

    try:
        response = parse_with_retry(
            client, system_prompt, prompt, FindingsBatchResponse,
            error_save_dir=None,
        )
        return response.findings, response.unknowns
    except Exception as e:
        logger.error("Cluster %s verification failed: %s", cluster_key, str(e)[:200])
        # Convert to unknowns on failure
        unknowns = [
            Unknown(
                id=f"U-{i + 1:02d}",
                what_was_checked=gf.message[:200] if gf.message else cluster_key,
                why_uncertain=f"LLM verification failed: {str(e)[:200]}",
                recommended_steps=["Retry verification manually"],
            )
            for i, gf in enumerate(findings)
        ]
        return [], unknowns


# --- Sub-phase 5b.5: Severity assignment (done inline during verification) ---


def run_deep_verify(
    input_data: Stage5bInput,
    client: LLMClient,
    max_concurrent: int = 3,
) -> Stage5bOutput:
    """Run Stage 5b: Deep verification of triaged findings."""
    logger.info(
        "Stage 5b: Deep verifying %d graded findings",
        len(input_data.graded_findings),
    )

    # Sub-phase 5b.1: Cluster
    clusters = _cluster_by_invariant_and_file(input_data.graded_findings)
    logger.info("Clustered into %d groups", len(clusters))

    # Sub-phase 5b.3: Parallel verification
    all_findings: list[Finding] = []
    all_unknowns: list[Unknown] = []

    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = {
            executor.submit(
                _verify_cluster, key, cluster, input_data.repo_path, client
            ): key
            for key, cluster in clusters.items()
        }

        for future in as_completed(futures):
            key = futures[future]
            try:
                findings, unknowns = future.result()
                all_findings.extend(findings)
                all_unknowns.extend(unknowns)
            except Exception as e:
                logger.error("Cluster %s failed: %s", key, str(e)[:200])

    # Assign sequential IDs (use model_copy to preserve immutability)
    all_findings = [
        f.model_copy(update={"id": f"V-{i + 1:02d}"})
        for i, f in enumerate(all_findings)
    ]
    all_unknowns = [
        u.model_copy(update={"id": f"U-{i + 1:02d}"})
        for i, u in enumerate(all_unknowns)
    ]

    logger.info(
        "Stage 5b complete: %d verified findings, %d unknowns",
        len(all_findings),
        len(all_unknowns),
    )
    return Stage5bOutput(verified_findings=all_findings, unknowns=all_unknowns)
