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
@click.option("--llm-api", type=click.Choice(["anthropic", "openai"]), default=None, help="LLM provider")
@click.option("--output-dir", default=None, help="Output directory for results")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
def scan(repo: str, stage: str | None, llm_api: str | None, output_dir: str | None, verbose: bool) -> None:
    """Run the full TEE audit pipeline against a repository."""
    from tee_audit.config import AuditConfig

    config = AuditConfig.load(llm_provider=llm_api, verbose=verbose, artifact_root=output_dir)

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
