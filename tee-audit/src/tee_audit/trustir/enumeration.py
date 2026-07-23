"""Enumeration items + index (iteration 3 — IRIS enumerate-then-classify).

A CodeQL "fetch" query enumerates real AST nodes (call-sites, function defs,
parameters, field reads) each carrying its AUTHORITATIVE identity: name,
declaring-type (Go: package + receiver type; Rust: none in rust-all 0.2.4),
signature, and file:line. These become ``EnumItem`` rows.

The LLM then CLASSIFIES a subset of these rows into role-tagged annotations
(``TrustAnnotation``). The resolver grounds each annotation against the
``EnumItemIndex`` — keyed Go by ``(name, declaring_type)`` and Rust by
``(name, signature)`` (Decision-R) — so locations/identity are inherited from
CodeQL, never proposed by the LLM.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnumItem:
    """One real AST node enumerated by a fetch query.

    ``declaring_type_pkg``/``declaring_type_type`` are populated for Go (the
    receiver-qualified package path + receiver type name); for Rust they are
    None (rust-all 0.2.4 exposes no qualification API — Decision-R).
    """

    kind: str  # "call" | "function" | "param" | "field_read"
    name: str
    file: str
    line: int
    declaring_type_pkg: str | None = None
    declaring_type_type: str | None = None
    signature: str | None = None
    arg_count: int | None = None  # calls only
    signature_text: str | None = None  # real param-type signature (Rust, inspection/disambiguation)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def declaring_type(self) -> str | None:
        """Qualified ``pkg.Type`` (Go) or ``Type`` / ``pkg`` if only one is set."""
        if self.declaring_type_pkg and self.declaring_type_type:
            return f"{self.declaring_type_pkg}.{self.declaring_type_type}"
        return self.declaring_type_type or self.declaring_type_pkg

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "declaring_type_pkg": self.declaring_type_pkg,
            "declaring_type_type": self.declaring_type_type,
            "declaring_type": self.declaring_type,
            "signature": self.signature,
            "signature_text": self.signature_text,
            "arg_count": self.arg_count,
        }


class EnumItemIndex:
    """Lookup index over EnumItems, keyed per language.

    Go key: ``(name, declaring_type)`` — kills name collisions (only
    ``pkg.ConfidentialEthBackend.Call`` matches, not geth's ``vmenv.Call``).
    Rust key: ``(name, signature)`` (Decision-R; no qualification API).
    """

    def __init__(self, items: list[EnumItem], language: str) -> None:
        self.language = language
        self._by_key: dict[tuple[str, str], list[EnumItem]] = defaultdict(list)
        self._by_name: dict[str, list[EnumItem]] = defaultdict(list)
        self._all: list[EnumItem] = list(items)
        for it in items:
            self._by_key[self._key(it)].append(it)
            self._by_name[it.name].append(it)

    def _key(self, it: EnumItem) -> tuple[str, str]:
        if self.language == "rust":
            return (it.name, it.signature or "")
        return (it.name, it.declaring_type or "")

    def lookup(
        self,
        name: str,
        *,
        declaring_type: str | None = None,
        signature: str | None = None,
    ) -> list[EnumItem]:
        if self.language == "rust":
            return list(self._by_key.get((name, signature or ""), []))
        return list(self._by_key.get((name, declaring_type or ""), []))

    def lookup_by_name(self, name: str) -> list[EnumItem]:
        """All enum items with this name, regardless of signature/declaring-type.

        Used by the Rust resolver's name-grounding fallback: when an LLM
        function/call annotation carries the wrong signature (it emitted the
        function name where the arity belongs), the resolver grounds by name and
        INHERITS the authoritative arity + location from CodeQL. Never used for
        param-SOURCEs — a bare param name is ambiguous across enclosing functions.
        """
        return list(self._by_name.get(name, []))

    def __len__(self) -> int:
        return len(self._all)

    def all_items(self) -> list[EnumItem]:
        return list(self._all)


def matches_exclusion(path: str, deny_globs: list[str]) -> bool:
    """Path exclusion test (any glob matches -> excluded).

    Supports ``**`` semantics: ``**/`` matches zero-or-more leading directories
    (so ``**/vendor/**`` also matches a top-level ``vendor/...``), ``/**`` matches
    zero-or-more trailing segments, bare ``**`` matches anything, and ``*`` matches
    a single path segment (no ``/``). Case-insensitive.
    """
    low = (path or "").lower().replace("\\", "/")
    return any(_glob_to_regex(g).match(low) for g in deny_globs)


def _glob_to_regex(glob: str):
    """Compile an exclusion glob (with ``**``) to an anchored case-insensitive regex.

    Token walk (avoids re-mangling inserted regex metacharacters):
      ``**/`` -> optional leading dirs ``(?:.*/)?`` (also matches at root)
      trailing ``/**`` -> optional trailing segments ``(?:/.*)?``
      bare ``**`` -> ``.*``   |   ``*`` -> single segment ``[^/]*``   |   ``?`` -> ``[^/]``
    """
    import re

    g = glob.lower()
    out = ["^"]
    i, n = 0, len(g)
    while i < n:
        if g[i : i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif g[i : i + 3] == "/**" and i + 3 == n:
            out.append("(?:/.*)?")
            i += 3
        elif g[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


__all__ = ["EnumItem", "EnumItemIndex", "matches_exclusion"]
