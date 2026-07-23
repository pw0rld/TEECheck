"""CLI entry point for tee-audit."""

from __future__ import annotations

import click
from rich.console import Console

from tee_audit import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="tee-audit")
def main() -> None:
    """tee-audit: TEE×Web3 static audit pipeline."""


@main.command()
@click.option("--repo", required=True, help="Target repository URL or local path")
@click.option("--stage", default=None, help="Run specific stage(s), e.g., '0-4' or '2'")
@click.option("--llm-api", type=click.Choice(["anthropic", "openai", "glm", "codex"]), default=None, help="LLM provider")
@click.option("--base-url", default=None, help="Custom API base URL for LLM provider")
@click.option("--output-dir", default=None, help="Output directory for results")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
def scan(repo: str, stage: str | None, llm_api: str | None, base_url: str | None, output_dir: str | None, verbose: bool) -> None:
    """Run the full TEE audit pipeline against a repository."""
    from tee_audit.config import AuditConfig

    config = AuditConfig.load(llm_provider=llm_api, llm_base_url=base_url, verbose=verbose, artifact_root=output_dir)

    # Configure logging based on verbose flag
    from tee_audit.logging import configure_logging
    configure_logging(verbose=config.verbose)

    # Parse stage range
    stages = None
    if stage:
        if "-" in stage:
            start, end = stage.split("-", 1)
            stages = range(int(start), int(end) + 1)
        else:
            stages = [int(stage)]

    console.print(f"[bold green]tee-audit[/] v{__version__}")
    console.print(f"Target: {repo}")
    console.print(f"LLM provider: {config.llm_provider}")
    if stages:
        console.print(f"Stages: {list(stages)}")
    console.print()

    from tee_audit.pipeline import run_pipeline, PipelineError

    try:
        run_pipeline(config, repo, stages=list(stages) if stages else None)
    except PipelineError as e:
        console.print(f"\n[red]Pipeline failed:[/] {e}")
        raise SystemExit(1) from e


@main.command("trustir")
@click.option("--repo", required=True, help="Target repository URL or local path")
@click.option("--twe", "twe_ids", multiple=True, help="Specific TWE id(s) to run (repeatable). Default: all 16.")
@click.option("--language", default=None, help="Override CodeQL language (go/javascript/rust)")
@click.option("--annotations", "annotations_path", default=None, help="Pre-built TrustAnnotationSet JSON (deterministic; skip LLM extraction)")
@click.option("--max-zones", "max_zones", type=int, default=None, help="v2 LLM: cap zone extraction to the N most trust-relevant zones (makes full extraction tractable)")
@click.option("--extract-workers", "extract_workers", type=int, default=1, help="v2 LLM: extract zones concurrently (1=serial)")
@click.option("--no-codeql", is_flag=True, help="Skip CodeQL DB build+run (binder/solver only)")
@click.option("--output-dir", default=None, help="Output directory for results")
@click.option("--llm-api", type=click.Choice(["anthropic", "openai", "glm", "codex"]), default=None, help="LLM provider")
@click.option("--base-url", default=None, help="Custom API base URL for LLM provider")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
def trustir(repo: str, twe_ids: tuple[str, ...], language: str | None, annotations_path: str | None, max_zones: int | None, extract_workers: int, no_codeql: bool, output_dir: str | None, llm_api: str | None, base_url: str | None, verbose: bool) -> None:
    """Run the deterministic TrustIR TEE-weakness pipeline (extract->bind->CodeQL->solve)."""
    from tee_audit.config import AuditConfig

    config = AuditConfig.load(llm_provider=llm_api, llm_base_url=base_url, verbose=verbose, artifact_root=output_dir)

    from tee_audit.logging import configure_logging
    configure_logging(verbose=config.verbose)

    console.print(f"[bold green]tee-audit trustir[/] v{__version__}")
    console.print(f"Target: {repo}  (language: {language or 'auto'})")
    if twe_ids:
        console.print(f"TWEs: {list(twe_ids)}")
    console.print()

    try:
        # --annotations for deterministic; otherwise LLM enumerate-then-classify.
        from tee_audit.trustir.pipeline import run_trustir

        summary = run_trustir(
            config, repo,
            twe_ids=list(twe_ids) or None,
            language=language,
            annotations_path=annotations_path,
            run_codeql=not no_codeql,
            max_zones=max_zones,
            max_workers=extract_workers,
        )
    except Exception as e:
        console.print(f"\n[red]TrustIR pipeline failed:[/] {e}")
        raise SystemExit(1) from e

    console.print(f"[green]Done.[/] findings={summary['finding_count']} codeql_run={summary['codeql_run']}")
    reports = summary.get("reports") or {}
    for kind, path in reports.items():
        if path:
            console.print(f"  {kind}: {path}")


@main.command("setup")
@click.argument("component", type=click.Choice(["codeql"]))
@click.option("--version", default=None, help="Version to install")
def setup(component: str, version: str | None) -> None:
    """Set up external dependencies."""
    if component == "codeql":
        _setup_codeql(version)


def _setup_codeql(version: str | None) -> None:
    """Download and configure CodeQL CLI binary."""
    from tee_audit.utils.codeql_check import download_codeql, find_codeql

    existing = find_codeql()
    if existing:
        console.print(f"[green]CodeQL already found at:[/] {existing}")
        return

    console.print("[bold]Setting up CodeQL...[/]")
    path = download_codeql(version)
    console.print(f"[green]CodeQL installed to:[/] {path}")
    console.print("Add to your PATH or set TEE_AUDIT_CODEQL_PATH in your environment.")


if __name__ == "__main__":
    main()
