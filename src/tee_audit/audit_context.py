"""AuditContext — persistence layer for pipeline resume support."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AuditContext:
    """Manages persisted stage outputs for resume support.

    This is NOT the inter-stage communication mechanism.
    Stages communicate via typed contracts (contracts.py).
    AuditContext only handles serialization/deserialization for resume.
    """

    def __init__(self, results_dir: Path, repo_path: Path, repo_commit_hash: str = "") -> None:
        self.results_dir = results_dir
        self.repo_path = repo_path
        self.repo_commit_hash = repo_commit_hash
        self._stage_outputs: dict[int, dict[str, Any]] = {}
        self._completed_stages: set[int] = set()
        results_dir.mkdir(parents=True, exist_ok=True)

    def save_stage(self, stage_num: int, output: BaseModel) -> None:
        """Persist a stage output to disk."""
        data = output.model_dump(mode="json")
        data["_repo_commit_hash"] = self.repo_commit_hash
        path = self.results_dir / f"stage{stage_num}_output.json"
        path.write_text(json.dumps(data, indent=2, default=str))
        self._stage_outputs[stage_num] = data
        self._completed_stages.add(stage_num)
        logger.info("Stage %d output saved to %s", stage_num, path)

    def load_stage(self, stage_num: int) -> dict[str, Any] | None:
        """Load a previously persisted stage output."""
        if stage_num in self._stage_outputs:
            return self._stage_outputs[stage_num]

        path = self.results_dir / f"stage{stage_num}_output.json"
        if not path.exists():
            return None

        data = json.loads(path.read_text())
        self._stage_outputs[stage_num] = data
        self._completed_stages.add(stage_num)
        logger.debug("Stage %d output loaded from %s", stage_num, path)
        return data

    def get_last_completed(self) -> int:
        """Return the highest completed stage number, or -1 if none."""
        if not self._completed_stages:
            return -1
        return max(self._completed_stages)

    def is_stage_completed(self, stage_num: int) -> bool:
        """Check if a stage has been completed."""
        return stage_num in self._completed_stages

    def verify_repo_hash(self, current_hash: str) -> bool:
        """Verify the current repo commit matches the persisted one."""
        if not self.repo_commit_hash:
            return True
        return self.repo_commit_hash == current_hash
