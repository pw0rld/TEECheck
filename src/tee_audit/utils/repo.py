"""Repository management utilities."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_repo_path(source: str) -> Path:
    """Resolve a repository source to a local path.

    If source is a URL, clone it. If it's a local path, return it directly.
    """
    if source.startswith(("https://", "git://", "git@")):
        return clone_repo(source)
    path = Path(source).resolve()
    if not path.exists():
        msg = f"Repository path does not exist: {path}"
        raise FileNotFoundError(msg)
    return path


def clone_repo(url: str, dest: Path | None = None) -> Path:
    """Clone a git repository to a local directory.

    Returns the path to the cloned repository.
    """
    if dest is None:
        # Derive directory name from URL
        name = url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        dest = Path("/tmp/tee-audit") / "repos" / name

    if dest.exists():
        logger.info("Repository already exists at %s, pulling latest", dest)
        subprocess.run(
            ["git", "pull", "--ff-only"],
            cwd=dest,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Cloning %s to %s", url, dest)

    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )
    return dest


def get_commit_hash(repo_path: Path) -> str:
    """Get the current commit hash of a git repository."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()
