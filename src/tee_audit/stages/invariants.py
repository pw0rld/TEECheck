"""Stage 2: Invariant extraction — LLM-powered security invariant identification."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage2Input, Stage2Output
from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.invariant import Invariant

logger = logging.getLogger(__name__)


class InvariantsResponse(BaseModel):
    """Wrapper for LLM invariant extraction response."""

    invariants: list[Invariant]


def run_invariants(input_data: Stage2Input, client: LLMClient, results_dir: Path | None = None) -> Stage2Output:
    """Run Stage 2: Extract security invariants via LLM."""
    logger.info("Stage 2: Extracting invariants")

    # Prepare context (truncated for token efficiency)
    fp_context = json.dumps(input_data.fingerprint.model_dump(mode="json"), indent=2, default=str)
    if len(fp_context) > 2000:
        fp_context = fp_context[:2000] + "\n...[truncated]"

    dossier_text = input_data.dossier
    if len(dossier_text) > 4000:
        dossier_text = dossier_text[:4000] + "\n...[truncated]"

    # Load and render prompt
    prompt = load_prompt(
        "invariants",
        fingerprint=fp_context,
        dossier=dossier_text,
    )

    system_prompt = (
        "You are a security analyst identifying trust-path invariants in a TEE-enabled Web3 system. "
        "Derive a SMALL set of security-relevant invariants from the architecture dossier. "
        "Each invariant must have: a unique ID (INV-NN format), a clear description, "
        "the trust path it guards, its analysis family (Flow/Guard/Binding/State/Config), "
        "sources, sinks, guards, failure modes, and whether CodeQL can express it. "
        "Keep the set small (5-15 invariants) and focused on security-relevant properties."
    )

    # Call LLM with structured output
    response = parse_with_retry(
        client, system_prompt, prompt, InvariantsResponse,
        error_save_dir=results_dir,
    )

    invariants = response.invariants
    logger.info("Stage 2 complete: %d invariants extracted", len(invariants))

    # Validate all invariants have required fields
    for inv in invariants:
        if not inv.id or not inv.description or not inv.family:
            logger.warning("Invariant missing required fields: %s", inv.id)

    return Stage2Output(invariants=invariants)
