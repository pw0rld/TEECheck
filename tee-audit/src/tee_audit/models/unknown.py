"""Unknown data model — items requiring manual validation."""

from __future__ import annotations

from pydantic import BaseModel

from tee_audit.models.finding import TaxonomyCategory


class Unknown(BaseModel):
    """An item that could not be fully resolved during automated verification."""

    id: str  # e.g., "U-01"
    title: str = ""  # short concise label, max 8 words
    what_was_checked: str
    why_uncertain: str
    recommended_steps: list[str]
    is_tee_relevant: bool = True
    tee_category: TaxonomyCategory | None = None
