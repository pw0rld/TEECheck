"""Pipeline orchestration — wires all 7 stages with typed contracts.

Sequential stage execution: stage_0 → stage_1 → ... → stage_6.
Each stage receives typed inputs and returns typed outputs.
AuditContext handles persistence for resume support only.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from tee_audit.audit_context import AuditContext
from tee_audit.config import AuditConfig
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
from tee_audit.llm.client import create_client, LLMClient
from tee_audit.stages.fingerprint import run_fingerprint
from tee_audit.stages.matrix import run_matrix
from tee_audit.stages.invariants import run_invariants
from tee_audit.stages.dossier import run_dossier
from tee_audit.stages.triage import run_triage
from tee_audit.stages.deep_verify import run_deep_verify
from tee_audit.stages.report import run_report
from tee_audit.stages.codeql import run_codeql
from tee_audit.utils.codeql_check import find_codeql
from tee_audit.utils.repo import get_commit_hash, resolve_repo_path

logger = logging.getLogger(__name__)
console = Console()

STAGE_NAMES = {
    0: "Fingerprint",
    1: "Dossier",
    2: "Invariants",
    3: "Analysis Matrix",
    4: "CodeQL Scan",
    5: "Triage + Deep Verify",
    6: "Report Assembly",
}

# Stages that halt the pipeline on failure (prerequisite for subsequent stages)
HALT_ON_FAILURE_STAGES = {0, 1, 2, 6}


class PipelineError(Exception):
    """Raised when a pipeline stage fails."""


def run_pipeline(
    config: AuditConfig,
    repo_source: str,
    stages: list[int] | None = None,
) -> AuditContext:
    """Run the full or partial audit pipeline.

    Args:
        config: Audit configuration
        repo_source: Repository URL or local path
        stages: Specific stages to run (None = all stages 0-6)

    Returns:
        AuditContext with persisted stage outputs
    """
    # Resolve repository
    repo_path = resolve_repo_path(repo_source)
    commit_hash = get_commit_hash(repo_path) if (repo_path / ".git").exists() else ""

    # Set up results directory
    results_dir = Path(config.artifact_root) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Initialize context for persistence
    ctx = AuditContext(
        results_dir=results_dir,
        repo_path=repo_path,
        repo_commit_hash=commit_hash,
    )

    # Default to all stages
    if stages is None:
        stages = list(range(7))

    # Create LLM client (only if LLM stages are needed)
    llm_client: LLMClient | None = None
    llm_stages = {1, 2, 5, 6}
    if any(s in llm_stages for s in stages):
        if not config.llm_api_key:
            console.print("[red]Error:[] LLM API key required for stages 1, 2, 5, 6.")
            console.print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")
            raise PipelineError("LLM API key not configured")
        llm_client = create_client(config.llm_provider, config.llm_api_key, config.llm_model)

    # Check CodeQL for stage 4
    if 4 in stages:
        codeql = find_codeql()
        if codeql is None:
            console.print("[red]Error:[] CodeQL not found for Stage 4.")
            console.print("Install with: tee-audit setup codeql")
            raise PipelineError("CodeQL not installed")

    # Run stages with progress display
    console.print(f"\n[bold]TEE Audit Pipeline[/] — {repo_path.name}")
    console.print(f"Commit: {commit_hash[:8] if commit_hash else 'N/A'}\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for stage_num in stages:
            task = progress.add_task(f"Stage {stage_num}: {STAGE_NAMES.get(stage_num, 'Unknown')}", total=None)
            start_time = time.time()

            try:
                _run_single_stage(stage_num, ctx, repo_path, config, llm_client, results_dir)
                elapsed = time.time() - start_time
                progress.update(task, description=f"[green]✓[/] Stage {stage_num}: {STAGE_NAMES.get(stage_num)} ({elapsed:.1f}s)")
            except Exception as e:
                elapsed = time.time() - start_time
                progress.update(task, description=f"[red]✗[/] Stage {stage_num}: {STAGE_NAMES.get(stage_num)} ({elapsed:.1f}s)")
                logger.error("Stage %d failed: %s", stage_num, str(e)[:500])

                if stage_num in HALT_ON_FAILURE_STAGES:
                    console.print(f"\n[red]Stage {stage_num} failed (required): {str(e)[:200]}[/]")
                    console.print(f"Results saved to {results_dir}")
                    raise PipelineError(f"Stage {stage_num} failed: {str(e)[:200]}") from e
                else:
                    console.print(f"\n[yellow]Stage {stage_num} failed (non-critical): {str(e)[:200]}[/]")
                    continue

    # Summary
    completed = ctx.get_last_completed()
    console.print(f"\n[bold green]Pipeline complete.[/] Completed stages: 0-{completed}")
    console.print(f"Results: {results_dir}")

    if llm_client:
        console.print(f"LLM tokens used: {llm_client.total_tokens_used:,}")

    return ctx


def _run_single_stage(
    stage_num: int,
    ctx: AuditContext,
    repo_path: Path,
    config: AuditConfig,
    llm_client: LLMClient | None,
    results_dir: Path,
) -> None:
    """Run a single pipeline stage, wiring inputs from previous outputs."""
    logger.info("=== Stage %d: %s ===", stage_num, STAGE_NAMES.get(stage_num, "Unknown"))

    if stage_num == 0:
        output = run_fingerprint(repo_path)
        ctx.save_stage(0, output)

    elif stage_num == 1:
        stage0_data = ctx.load_stage(0)
        if not stage0_data:
            raise PipelineError("Stage 0 output required. Run stage 0 first.")
        stage0 = Stage0Output.model_validate(stage0_data)
        assert llm_client is not None
        output = run_dossier(
            Stage1Input(repo_path=repo_path, fingerprint=stage0.fingerprint),
            llm_client,
            results_dir=results_dir,
        )
        ctx.save_stage(1, output)

    elif stage_num == 2:
        stage0_data = ctx.load_stage(0)
        stage1_data = ctx.load_stage(1)
        if not stage0_data or not stage1_data:
            raise PipelineError("Stages 0 and 1 outputs required. Run stages 0-1 first.")
        stage0 = Stage0Output.model_validate(stage0_data)
        stage1 = Stage1Output.model_validate(stage1_data)
        assert llm_client is not None
        output = run_invariants(
            Stage2Input(fingerprint=stage0.fingerprint, dossier=stage1.dossier),
            llm_client,
            results_dir=results_dir,
        )
        ctx.save_stage(2, output)

    elif stage_num == 3:
        stage2_data = ctx.load_stage(2)
        if not stage2_data:
            raise PipelineError("Stage 2 output required. Run stage 2 first.")
        stage2 = Stage2Output.model_validate(stage2_data)
        output = run_matrix(Stage3Input(invariants=stage2.invariants))
        ctx.save_stage(3, output)

    elif stage_num == 4:
        stage2_data = ctx.load_stage(2)
        if not stage2_data:
            raise PipelineError("Stage 2 output required for CodeQL query selection.")
        stage2 = Stage2Output.model_validate(stage2_data)
        codeql_path = find_codeql()
        assert codeql_path is not None
        artifact_root = Path(config.artifact_root)
        output = run_codeql(
            Stage4Input(repo_path=repo_path, invariants=stage2.invariants),
            codeql_path=codeql_path,
            artifact_root=artifact_root,
        )
        ctx.save_stage(4, output)

    elif stage_num == 5:
        # Run 5a (triage) then 5b (deep verify) sequentially
        stage2_data = ctx.load_stage(2)
        stage4_data = ctx.load_stage(4)
        if not stage2_data:
            raise PipelineError("Stage 2 output required for triage.")
        stage2 = Stage2Output.model_validate(stage2_data)

        # Stage 5a: Triage
        sarif_path = Path(stage4_data["sarif_path"]) if stage4_data else None
        if sarif_path and sarif_path.exists():
            triage_output = run_triage(
                Stage5aInput(sarif_path=sarif_path, invariants=stage2.invariants)
            )
            ctx.save_stage(5, triage_output)

            # Stage 5b: Deep verify
            assert llm_client is not None
            verify_output = run_deep_verify(
                Stage5bInput(
                    graded_findings=triage_output.graded_findings,
                    invariants=stage2.invariants,
                    repo_path=repo_path,
                ),
                llm_client,
                max_concurrent=config.max_concurrent_llm_calls,
            )
            # Save 5b output separately
            ctx.save_stage(6, verify_output)  # Use 6 as 5b index for persistence
        else:
            logger.warning("No SARIF file found, skipping triage and deep verification")

    elif stage_num == 6:
        stage0_data = ctx.load_stage(0)
        stage2_data = ctx.load_stage(2)
        stage5b_data = ctx.load_stage(6)  # 5b was saved at index 6
        if not all([stage0_data, stage2_data]):
            raise PipelineError("Stages 0 and 2 outputs required for report.")
        stage0 = Stage0Output.model_validate(stage0_data)
        stage2 = Stage2Output.model_validate(stage2_data)
        stage5b = Stage5bOutput.model_validate(stage5b_data) if stage5b_data else Stage5bOutput(verified_findings=[], unknowns=[])

        # Load triage for positive guards
        stage5a_data = ctx.load_stage(5)
        positive_guards = []
        if stage5a_data:
            stage5a = Stage5aOutput.model_validate(stage5a_data)
            positive_guards = stage5a.positive_guards

        assert llm_client is not None
        output = run_report(
            Stage6Input(
                fingerprint=stage0.fingerprint,
                invariants=stage2.invariants,
                findings=stage5b.verified_findings,
                positive_guards=positive_guards,
                unknowns=stage5b.unknowns,
            ),
            llm_client,
            results_dir=results_dir,
        )
        ctx.save_stage(7, output)  # Use 7 as stage 6 output index

    else:
        raise PipelineError(f"Unknown stage number: {stage_num}")
