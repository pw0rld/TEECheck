"""Repository management utilities."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _repo_name_from_source(source: str) -> str:
    """Extract the repository name from a URL or local path."""
    if source.startswith(("https://", "git://", "git@")):
        name = source.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name
    return Path(source).name


def resolve_repo_path(
    source: str,
    artifact_root: str | None = None,
    audit_dir: Path | None = None,
) -> Path:
    """Resolve a repository source to a local path.

    Layout (nested):
        <artifact_root>/
            <name>-audit/
                <name>/          # repo source
                artifact/        # intermediate artifacts
                results/         # reports + stage outputs

    If audit_dir is provided, the repo is cloned inside it at audit_dir/<name>.
    Otherwise falls back to the legacy sibling layout for backwards compatibility.
    """
    if audit_dir is not None:
        name = _repo_name_from_source(source)
        dest = audit_dir / name
    else:
        root = Path(artifact_root) if artifact_root else Path("output")
        name = _repo_name_from_source(source)
        dest = root / name

    if source.startswith(("https://", "git://", "git@")):
        return clone_repo(source, dest=dest)

    path = Path(source).resolve()
    if not path.exists():
        msg = f"Repository path does not exist: {path}"
        raise FileNotFoundError(msg)

    if dest.exists():
        logger.info("Repository already exists at %s, updating", dest)
        subprocess.run(
            ["git", "fetch", "--all"],
            cwd=dest,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Cloning local repo %s to %s", path, dest)
        subprocess.run(
            ["git", "clone", "--local", str(path), str(dest)],
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        )
    return dest


def clone_repo(url: str, dest: Path | None = None, artifact_root: str | None = None) -> Path:
    """Clone a git repository to a local directory."""
    if dest is None:
        name = url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        root = Path(artifact_root) if artifact_root else Path("output")
        dest = root / name

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
