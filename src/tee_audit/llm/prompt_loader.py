"""Prompt template loader using importlib.resources."""

from __future__ import annotations

import importlib.resources
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_PROMPTS_PACKAGE = "tee_audit.prompts"


def load_prompt(name: str, **kwargs: str) -> str:
    """Load a prompt template and substitute variables.

    Templates are .md files in tee_audit/prompts/.
    Variables use {{name}} syntax.

    Args:
        name: Template filename without .md extension (e.g., "dossier")
        **kwargs: Variables to substitute in the template

    Returns:
        The rendered prompt text
    """
    template_path = _find_template(name)
    template = template_path.read_text()

    # Substitute {{variable}} placeholders
    def replacer(match: re.Match) -> str:
        var_name = match.group(1)
        if var_name in kwargs:
            value = kwargs[var_name]
            # Sanitize: truncate long values to prevent context overflow
            if len(value) > 2000:
                logger.warning("Truncating prompt variable '%s' from %d to 2000 chars", var_name, len(value))
                value = value[:2000] + "\n...[truncated]"
            return value
        logger.warning("Prompt variable '%s' not provided, leaving placeholder", var_name)
        return match.group(0)

    return re.sub(r"\{\{(\w+)\}\}", replacer, template)


def _find_template(name: str) -> Path:
    """Find a prompt template file."""
    # Try direct path first (for development)
    prompts_dir = Path(__file__).parent / "prompts"
    if not prompts_dir.exists():
        prompts_dir = Path(__file__).parent.parent / "prompts"

    template = prompts_dir / f"{name}.md"
    if template.exists():
        return template

    # Try importlib.resources as fallback
    try:
        ref = importlib.resources.files(_PROMPTS_PACKAGE).joinpath(f"{name}.md")
        with importlib.resources.as_file(ref) as path:
            if path.exists():
                return path
    except (ModuleNotFoundError, TypeError):
        pass

    msg = f"Prompt template not found: {name}.md"
    raise FileNotFoundError(msg)
