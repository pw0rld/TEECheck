"""Symbol indexing for the annotation resolver (iteration 2).

No tree-sitter dependency: function definitions and call sites are found via
language-aware regex over file lines. Good enough to resolve LLM name anchors to
real ``(file, line)`` locations and to reject names that do not exist.
"""

from __future__ import annotations

import re
from pathlib import Path

_CODE_EXTS = {".go", ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs"}
_SKIP_DIRS = {".git", "vendor", "node_modules", "target", "build", ".codeql",
              "third_party", "docs", "testdata", "test_data"}

# Function-definition patterns per extension. Group 1 = function name.
_DEF_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".go": [
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s+)?([A-Za-z_]\w*)\s*[\[(]"),
    ],
    ".rs": [
        re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_]\w*)\s*[\[(<]"),
    ],
    ".js": [
        re.compile(r"^\s*function\s+([A-Za-z_$][\w$]*)\s*\("),
        re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:async\s+)?\(?[^)]*\)?\s*=>"),
        re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
        re.compile(r"^\s*class\s+([A-Za-z_$][\w$]*)"),
    ],
    ".ts": [
        re.compile(r"^\s*function\s+([A-Za-z_$][\w$]*)\s*[\(<]"),
        re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:async\s+)?\(?[^)]*\)?\s*=>"),
        re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*[\{:]"),
        re.compile(r"^\s*class\s+([A-Za-z_$][\w$]*)"),
    ],
    ".tsx": [],  # reuse .ts
    ".jsx": [],  # reuse .js
    ".mjs": [],  # reuse .js
}


def _ext_patterns(ext: str) -> list[re.Pattern[str]]:
    if ext in (".tsx", ".ts"):
        return _DEF_PATTERNS[".ts"]
    if ext in (".jsx", ".mjs", ".js"):
        return _DEF_PATTERNS[".js"]
    return _DEF_PATTERNS.get(ext, [])


def _iter_code_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for root, dirs, names in __import__("os").walk(repo_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            if Path(n).suffix in _CODE_EXTS and not _is_test_file(n):
                files.append(Path(root) / n)
    return files


def _is_test_file(name: str) -> bool:
    return ("_test" in name) or name.endswith(".test.js") or name.endswith(".spec.ts")


def bare_name(name: str) -> str:
    """Strip a package/type qualifier: ``pdo.NewEpidLinkableVerifier`` -> ``NewEpidLinkableVerifier``.

    LLMs frequently emit package-qualified Go names (``pkg.Func``) or method
    receivers; the index keys on bare identifiers, so qualified names must be
    normalized before lookup.
    """
    return name.rsplit(".", 1)[-1] if "." in name else name


def index_function_defs(repo_root: Path) -> dict[str, list[tuple[str, int]]]:
    """Return ``{function_name: [(relative_file, line), ...]}`` for the repo."""
    repo_root = Path(repo_root).resolve()
    index: dict[str, list[tuple[str, int]]] = {}
    for fp in _iter_code_files(repo_root):
        ext = fp.suffix
        patterns = _ext_patterns(ext)
        if not patterns:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(fp.relative_to(repo_root))
        for i, line in enumerate(text.splitlines(), 1):
            for pat in patterns:
                m = pat.match(line)
                if m:
                    name = m.group(1)
                    index.setdefault(name, []).append((rel, i))
                    break
    return index


def find_call_sites(repo_root: Path, name: str) -> list[tuple[str, int]]:
    """Return all ``(relative_file, line)`` where ``name(`` is called."""
    if not name or not re.match(r"^[A-Za-z_$][\w$]*$", name):
        return []
    repo_root = Path(repo_root).resolve()
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    sites: list[tuple[str, int]] = []
    for fp in _iter_code_files(repo_root):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(fp.relative_to(repo_root))
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                sites.append((rel, i))
    return sites


__all__ = ["index_function_defs", "find_call_sites"]
