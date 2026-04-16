"""Stage 1: Dossier — LLM-powered architecture description."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage1Input, Stage1Output
from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt
from tee_audit.llm.response_parser import parse_with_retry

logger = logging.getLogger(__name__)


class DossierResponse(BaseModel):
    """Wrapper for LLM dossier response (Anthropic tool-use requires object, not bare string)."""

    executive_summary: str
    architecture_overview: str
    trust_boundary_description: str
    key_components: list[str]
    sections: dict[str, str]


def run_dossier(input_data: Stage1Input, client: LLMClient, results_dir: Path | None = None) -> Stage1Output:
    """Run Stage 1: Generate architecture dossier via LLM."""
    logger.info("Stage 1: Generating dossier for %s", input_data.repo_path)

    # Prepare fingerprint context (truncated for token efficiency)
    fp = input_data.fingerprint
    fp_context = json.dumps(fp.model_dump(mode="json"), indent=2, default=str)
    if len(fp_context) > 3000:
        fp_context = fp_context[:3000] + "\n...[truncated]"

    # Build repo structure summary
    repo_structure = _build_repo_structure(input_data.repo_path)

    # Load and render prompt
    prompt = load_prompt(
        "dossier",
        fingerprint=fp_context,
        repo_structure=repo_structure,
    )

    system_prompt = (
        "You are a security architect performing a TEE audit of a Web3 project. "
        "Generate a clear, structured architecture dossier based on the fingerprint data. "
        "Be factual and grounded in the evidence provided. Do not speculate beyond what the data shows."
    )

    # Call LLM with structured output
    response = parse_with_retry(
        client, system_prompt, prompt, DossierResponse,
        error_save_dir=results_dir,
    )

    # Assemble full dossier text
    dossier_text = f"# Architecture Dossier\n\n"
    dossier_text += f"## Executive Summary\n{response.executive_summary}\n\n"
    dossier_text += f"## Architecture Overview\n{response.architecture_overview}\n\n"
    dossier_text += f"## Trust Boundaries\n{response.trust_boundary_description}\n\n"
    dossier_text += f"## Key Components\n"
    for comp in response.key_components:
        dossier_text += f"- {comp}\n"

    logger.info("Stage 1 complete: dossier generated (%d chars)", len(dossier_text))
    return Stage1Output(dossier=dossier_text, sections=response.sections)


def _build_repo_structure(repo_path: Path, max_depth: int = 2, max_entries: int = 30) -> str:
    """Build a concise repo directory structure summary."""
    lines: list[str] = []
    try:
        for item in sorted(repo_path.iterdir()):
            if item.name.startswith(".") or item.name in {"node_modules", "target", "__pycache__", "vendor"}:
                continue
            if item.is_dir():
                lines.append(f"{item.name}/")
                if max_depth > 1:
                    for child in sorted(item.iterdir())[:10]:
                        if child.name.startswith("."):
                            continue
                        prefix = "  " + ("├── " if child != sorted(item.iterdir())[-1] else "└── ")
                        lines.append(f"{prefix}{child.name}{'/' if child.is_dir() else ''}")
            else:
                lines.append(item.name)
            if len(lines) >= max_entries:
                lines.append("... [truncated]")
                break
    except PermissionError:
        lines.append("[permission denied]")
    return "\n".join(lines)
