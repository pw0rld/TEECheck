"""Line-level symbol index: read a file's lines and locate name occurrences.

No tree-sitter, no AST. Case-sensitive substring search on the last segment of a
qualified name. This is intentionally conservative: a match means the name token
is literally present on the line, nothing more.
"""

from __future__ import annotations

from pathlib import Path


def read_lines(file_path: Path) -> list[str]:
    """Return the lines of a file (without trailing newlines). Missing file -> []."""
    if not file_path.is_file():
        return []
    return file_path.read_text(encoding="utf-8", errors="replace").splitlines()


def find_name_occurrences(lines: list[str], name: str) -> list[int]:
    """Return 1-based line numbers where ``name`` occurs (case-sensitive substring)."""
    if not name:
        return []
    return [i + 1 for i, line in enumerate(lines) if name in line]


def last_segment(qualified_name: str) -> str:
    """Return the last ``.``-separated segment of a qualified name."""
    if not qualified_name:
        return ""
    return qualified_name.rsplit(".", 1)[-1]
