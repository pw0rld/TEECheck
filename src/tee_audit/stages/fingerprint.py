"""Stage 0: Fingerprint — TEE signal detection.

Pure Python port of collect_tee_signals.sh. Uses pathlib + re only.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from pathlib import Path

from tee_audit.contracts import Stage0Output
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.patterns.tee_signals import (
    BUILD_FLAG_PATTERNS,
    CRITICAL_PATH_DIRS,
    EXTENSION_LANGUAGE_MAP,
    TEE_PLATFORM_PATTERNS,
    TRUST_ARTIFACT_PATTERNS,
    WEB3_ROLE_PATTERNS,
)

logger = logging.getLogger(__name__)

# Binary file extensions to skip
SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".so", ".dylib", ".dll", ".o", ".a", ".lib",
    ".exe", ".bin", ".dat", ".db", ".sqlite",
    ".woff", ".woff2", ".ttf", ".eot",
})


def _scan_patterns(root: Path, patterns: dict[str, str], max_matches: int = 30) -> dict[str, list[str]]:
    """Scan repo for regex patterns, returning matched lines per category.

    Uses pure Python pathlib + re. Walks the directory tree once per category.
    """
    results: dict[str, list[str]] = {}
    for label, pattern in patterns.items():
        matches: list[str] = []
        compiled = re.compile(pattern, re.IGNORECASE)
        try:
            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix in SKIP_EXTENSIONS:
                    continue
                # Skip common non-source directories
                parts = file_path.relative_to(root).parts
                if any(p in {".git", "node_modules", "__pycache__", "target", ".venv", "vendor"} for p in parts):
                    continue
                try:
                    text = file_path.read_text(errors="ignore")
                    for i, line in enumerate(text.splitlines(), 1):
                        if compiled.search(line):
                            rel = file_path.relative_to(root)
                            matches.append(f"{rel}:{i}: {line.strip()}")
                            if len(matches) >= max_matches:
                                break
                except (OSError, ValueError):
                    continue
                if len(matches) >= max_matches:
                    break
        except PermissionError:
            logger.warning("Permission denied scanning %s", root)
        results[label] = matches if matches else []
    return results


def _enumerate_extensions(root: Path, top_n: int = 12) -> dict[str, int]:
    """Count file extensions in the repository."""
    counts: Counter[str] = Counter()
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        parts = file_path.relative_to(root).parts
        if any(p in {".git", "node_modules", "__pycache__", "target", ".venv"} for p in parts):
            continue
        ext = file_path.suffix.lstrip(".")
        if ext:
            counts[ext] += 1
    return dict(counts.most_common(top_n))


def _detect_codeql_languages(extensions: dict[str, int]) -> list[str]:
    """Map file extensions to CodeQL-supported languages."""
    languages: set[str] = set()
    for ext in extensions:
        if ext in EXTENSION_LANGUAGE_MAP:
            languages.add(EXTENSION_LANGUAGE_MAP[ext])
    return sorted(languages)


def _find_critical_paths(root: Path, max_depth: int = 3) -> list[str]:
    """Find directories matching critical path patterns."""
    paths: list[str] = []
    for dir_path in root.rglob("*"):
        if not dir_path.is_dir():
            continue
        # Check depth
        depth = len(dir_path.relative_to(root).parts)
        if depth > max_depth:
            continue
        dir_name = dir_path.name.lower()
        if any(pattern in dir_name for pattern in CRITICAL_PATH_DIRS):
            paths.append(str(dir_path.relative_to(root)))
            if len(paths) >= 12:
                break
    return paths


def run_fingerprint(repo_path: Path) -> Stage0Output:
    """Run Stage 0: Fingerprint the repository for TEE and Web3 signals.

    Pure Python implementation using pathlib + re. No external dependencies.
    """
    logger.info("Stage 0: Fingerprinting %s", repo_path)

    if not repo_path.exists():
        msg = f"Repository path does not exist: {repo_path}"
        raise FileNotFoundError(msg)

    # Enumerate file extensions and detect languages
    top_extensions = _enumerate_extensions(repo_path)
    codeql_languages = _detect_codeql_languages(top_extensions)

    # Scan for TEE platform signals
    tee_platforms = _scan_patterns(repo_path, TEE_PLATFORM_PATTERNS)

    # Scan for Web3 role signals
    web3_roles = _scan_patterns(repo_path, WEB3_ROLE_PATTERNS)

    # Scan for trust artifact signals
    trust_artifacts = _scan_patterns(repo_path, TRUST_ARTIFACT_PATTERNS)

    # Scan for build flag signals
    build_flags = _scan_patterns(repo_path, BUILD_FLAG_PATTERNS)

    # Find critical paths
    critical_paths = _find_critical_paths(repo_path)

    fingerprint = Fingerprint(
        repo_root=str(repo_path),
        top_extensions=top_extensions,
        codeql_languages=codeql_languages,
        tee_platforms=tee_platforms,
        web3_roles=web3_roles,
        trust_artifacts=trust_artifacts,
        build_flags=build_flags,
        critical_paths=critical_paths,
    )

    logger.info(
        "Stage 0 complete: %d languages, %d TEE signals, %d critical paths",
        len(codeql_languages),
        sum(len(v) for v in tee_platforms.values()),
        len(critical_paths),
    )

    return Stage0Output(fingerprint=fingerprint)
