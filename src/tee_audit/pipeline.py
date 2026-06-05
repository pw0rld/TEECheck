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
    Stage7Input,
    Stage7Output,
)
from tee_audit.llm.client import create_client, LLMClient
from tee_audit.stages.fingerprint import run_fingerprint
from tee_audit.stages.matrix import run_matrix
from tee_audit.stages.invariants import run_invariants
from tee_audit.stages.dossier import run_dossier
from tee_audit.stages.triage import run_triage
from tee_audit.stages.deep_verify import run_deep_verify, postprocess_boundary_completeness
from tee_audit.stages.report import run_report
from tee_audit.stages.report_review import run_report_review, _verify_invariants_parallel
from tee_audit.stages.codeql import run_codeql
from tee_audit.utils.codeql_check import find_codeql
from tee_audit.utils.repo import _repo_name_from_source, get_commit_hash, resolve_repo_path
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.logging import configure_logging

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
    7: "Report Review & Refinement",
}

# Stages that halt the pipeline on failure (prerequisite for subsequent stages)
HALT_ON_FAILURE_STAGES = {0, 1, 2, 4, 6}

STAGE_TEMPERATURES: dict[int, float] = {
    1: 0.0,   # Dossier — structured architecture extraction
    2: 0.0,   # Invariants — structured security properties
    4: 0.0,   # CodeQL — deterministic query generation
    5: 0.5,   # Deep Verify (5b) — vulnerability discovery
    6: 0.0,   # Report — structured narrative
    7: 0.3,   # Report Review — balanced creativity for finding real issues
}


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
    # Configure logging and console
    configure_logging(verbose=config.verbose)
    run_console = Console(no_color=config.no_color)

    # Compute nested audit layout from source name (before cloning)
    repo_name = _repo_name_from_source(repo_source)
    audit_dir = Path(config.artifact_root) / f"{repo_name}-audit"
    artifact_dir = audit_dir / "artifact"
    results_dir = audit_dir / "results"

    # Resolve repository into the nested layout
    repo_path = resolve_repo_path(repo_source, artifact_root=config.artifact_root, audit_dir=audit_dir)
    commit_hash = get_commit_hash(repo_path) if (repo_path / ".git").exists() else ""

    # Ensure all nested directories exist
    artifact_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Initialize context for persistence
    ctx = AuditContext(
        results_dir=results_dir,
        repo_path=repo_path,
        repo_commit_hash=commit_hash,
    )

    # Default to all stages
    if stages is None:
        stages = list(range(8))

    # Create LLM client (only if LLM stages are needed)
    llm_client: LLMClient | None = None
    llm_stages = {1, 2, 4, 5, 6, 7}
    if any(s in llm_stages for s in stages):
        if not config.llm_api_key:
            run_console.print("[red]Error:[] LLM API key required for stages 1, 2, 5, 6.")
            run_console.print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")
            raise PipelineError("LLM API key not configured")
        llm_client = create_client(config.llm_provider, config.llm_api_key, config.llm_model, config.llm_base_url)

    # Check CodeQL for stage 4
    if 4 in stages:
        codeql = Path(config.codeql_path) if config.codeql_path else find_codeql()
        if codeql is None:
            run_console.print("[red]Error:[] CodeQL not found for Stage 4.")
            run_console.print("Install with: tee-audit setup codeql")
            raise PipelineError("CodeQL not installed")

    # Run stages with progress display
    run_console.print(f"\n[bold]TEE Audit Pipeline[/] — {repo_path.name}")
    run_console.print(f"Commit: {commit_hash[:8] if commit_hash else 'N/A'}\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=run_console,
    ) as progress:
        for stage_num in stages:
            task = progress.add_task(f"Stage {stage_num}: {STAGE_NAMES.get(stage_num, 'Unknown')}", total=None)
            start_time = time.time()

            try:
                _run_single_stage(stage_num, ctx, repo_path, config, llm_client, results_dir, artifact_dir)
                elapsed = time.time() - start_time
                progress.update(task, description=f"[green]✓[/] Stage {stage_num}: {STAGE_NAMES.get(stage_num)} ({elapsed:.1f}s)")
            except Exception as e:
                elapsed = time.time() - start_time
                progress.update(task, description=f"[red]✗[/] Stage {stage_num}: {STAGE_NAMES.get(stage_num)} ({elapsed:.1f}s)")
                logger.error("Stage %d failed: %s", stage_num, str(e)[:500])

                if stage_num in HALT_ON_FAILURE_STAGES:
                    run_console.print(f"\n[red]Stage {stage_num} failed (required): {str(e)[:200]}[/]")
                    run_console.print(f"Results saved to {results_dir}")
                    raise PipelineError(f"Stage {stage_num} failed: {str(e)[:200]}") from e
                else:
                    run_console.print(f"\n[yellow]Stage {stage_num} failed (non-critical): {str(e)[:200]}[/]")
                    continue

    # Summary
    completed = ctx.get_last_completed()
    run_console.print(f"\n[bold green]Pipeline complete.[/] Completed stages: 0-{completed}")
    run_console.print(f"Results: {results_dir}")

    if llm_client:
        run_console.print(f"LLM tokens used: {llm_client.total_tokens_used:,}")

    return ctx


def _run_single_stage(
    stage_num: int,
    ctx: AuditContext,
    repo_path: Path,
    config: AuditConfig,
    llm_client: LLMClient | None,
    results_dir: Path,
    artifact_dir: Path | None = None,
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
        if llm_client is None:
            raise PipelineError("LLM client required for stage 1 but not configured")
        output = run_dossier(
            Stage1Input(repo_path=repo_path, fingerprint=stage0.fingerprint),
            llm_client,
            results_dir=results_dir,
            temperature=STAGE_TEMPERATURES[1],
        )
        ctx.save_stage(1, output)

    elif stage_num == 2:
        stage0_data = ctx.load_stage(0)
        stage1_data = ctx.load_stage(1)
        if not stage0_data or not stage1_data:
            raise PipelineError("Stages 0 and 1 outputs required. Run stages 0-1 first.")
        stage0 = Stage0Output.model_validate(stage0_data)
        stage1 = Stage1Output.model_validate(stage1_data)
        if llm_client is None:
            raise PipelineError("LLM client required for stage 2 but not configured")
        output = run_invariants(
            Stage2Input(fingerprint=stage0.fingerprint, dossier=stage1.dossier),
            llm_client,
            results_dir=results_dir,
            temperature=STAGE_TEMPERATURES[2],
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
        # Load manifest entry points from stage 0 fingerprint
        manifest_eps: list[str] = []
        stage0_data = ctx.load_stage(0)
        if stage0_data:
            stage0 = Stage0Output.model_validate(stage0_data)
            manifest_eps = [
                ep["function"] for ep in stage0.fingerprint.manifest_entry_points
            ]
        codeql_path = Path(config.codeql_path) if config.codeql_path else find_codeql()
        if codeql_path is None:
            raise PipelineError("CodeQL binary not found")
        output = run_codeql(
            Stage4Input(repo_path=repo_path, invariants=stage2.invariants, manifest_entry_points=manifest_eps),
            codeql_path=codeql_path,
            artifact_root=artifact_dir,
            client=llm_client,
            temperature=STAGE_TEMPERATURES[4],
        )
        ctx.save_stage(4, output)

    elif stage_num == 5:
        # Run 5a (triage) then 5b (deep verify) sequentially
        stage0_data = ctx.load_stage(0)
        stage2_data = ctx.load_stage(2)
        stage4_data = ctx.load_stage(4)
        if not stage2_data:
            raise PipelineError("Stage 2 output required for triage.")
        stage2 = Stage2Output.model_validate(stage2_data)
        stage0 = Stage0Output.model_validate(stage0_data) if stage0_data else None
        fingerprint = stage0.fingerprint if stage0 else None

        # Stage 5a: Triage
        sarif_path = Path(stage4_data["sarif_path"]) if stage4_data and "sarif_path" in stage4_data else None
        if sarif_path and sarif_path.exists():
            triage_output = run_triage(
                Stage5aInput(sarif_path=sarif_path, invariants=stage2.invariants)
            )
            ctx.save_stage(5, triage_output)

            # Stage 5b: Deep verify
            if llm_client is None:
                raise PipelineError("LLM client required for stage 5b but not configured")
            verify_output = run_deep_verify(
                Stage5bInput(
                    graded_findings=triage_output.graded_findings,
                    invariants=stage2.invariants,
                    repo_path=repo_path,
                    fingerprint=fingerprint,
                ),
                llm_client,
                max_concurrent=config.max_concurrent_llm_calls,
                temperature=STAGE_TEMPERATURES[5],
                no_escalate=config.no_escalate,
            )
            # Save 5b output separately (use slot 55 to avoid collision with stage 6)
            ctx.save_stage(55, verify_output)
        else:
            # Fallback: CodeQL failed/skipped, use LLM-based invariant verification
            logger.warning("No SARIF file found. Running LLM-based invariant verification as fallback.")
            if llm_client is None:
                raise PipelineError("LLM client required for fallback verification but not configured")
            fallback_findings, fallback_guards, fallback_unknowns = _verify_invariants_parallel(
                stage2.invariants, repo_path, llm_client,
                max_concurrent=config.max_concurrent_llm_calls,
                temperature=STAGE_TEMPERATURES[5],
            )
            # Apply boundary completeness to LLM-fallback findings too
            fallback_findings = postprocess_boundary_completeness(
                fallback_findings, repo_path, fingerprint, llm_client,
            )
            # Save as Stage5aOutput (empty triage) and Stage5bOutput (LLM findings)
            ctx.save_stage(5, Stage5aOutput(graded_findings=[], positive_guards=fallback_guards))
            ctx.save_stage(55, Stage5bOutput(verified_findings=fallback_findings, unknowns=fallback_unknowns))
            logger.info(
                "LLM fallback produced %d findings, %d guards, %d unknowns",
                len(fallback_findings), len(fallback_guards), len(fallback_unknowns),
            )

    elif stage_num == 6:
        stage0_data = ctx.load_stage(0)
        stage2_data = ctx.load_stage(2)
        stage5b_data = ctx.load_stage(55)  # 5b was saved at index 55
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

        # Load dossier for diagram generation
        stage1_data = ctx.load_stage(1)
        dossier_sections: dict[str, str] = {}
        key_components: list[str] = []
        if stage1_data:
            stage1 = Stage1Output.model_validate(stage1_data)
            dossier_sections = stage1.sections
            key_components = stage1.key_components
        if not key_components and stage1_data:
            logger.warning("Architecture diagram built from fallback data (cached stage 1 lacks key_components). Re-run stage 1 for richer diagram.")

        if llm_client is None:
            raise PipelineError("LLM client required for stage 6 but not configured")
        output = run_report(
            Stage6Input(
                fingerprint=stage0.fingerprint,
                invariants=stage2.invariants,
                findings=stage5b.verified_findings,
                positive_guards=positive_guards,
                unknowns=stage5b.unknowns,
                dossier_sections=dossier_sections,
                key_components=key_components,
                zone_map_path=artifact_dir / "zone_map.json" if artifact_dir else None,
            ),
            llm_client,
            results_dir=results_dir,
            temperature=STAGE_TEMPERATURES[6],
        )
        ctx.save_stage(6, output)

    elif stage_num == 7:
        stage6_data = ctx.load_stage(6)
        stage2_data = ctx.load_stage(2)
        if not stage6_data:
            raise PipelineError("Stage 6 output required. Run stage 6 first.")
        if not stage2_data:
            raise PipelineError("Stage 2 output required for invariant verification.")
        stage6 = Stage6Output.model_validate(stage6_data)
        stage2 = Stage2Output.model_validate(stage2_data)
        if llm_client is None:
            raise PipelineError("LLM client required for stage 7 but not configured")
        output = run_report_review(
            stage6_output=stage6,
            invariants=stage2.invariants,
            repo_path=repo_path,
            client=llm_client,
            results_dir=results_dir,
            temperature=STAGE_TEMPERATURES.get(7, 0.3),
        )
        ctx.save_stage(7, output)

    else:
        raise PipelineError(f"Unknown stage number: {stage_num}")
