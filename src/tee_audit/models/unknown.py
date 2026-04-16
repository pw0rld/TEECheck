"""Unknown data model — items requiring manual validation."""

from __future__ import annotations

from pydantic import BaseModel


class Unknown(BaseModel):
    """An item that could not be fully resolved during automated verification."""

    id: str  # e.g., "U-01"
    what_was_checked: str
    why_uncertain: str
    recommended_steps: list[str]
