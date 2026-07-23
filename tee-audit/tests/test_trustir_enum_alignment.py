"""Enum-registry alignment test (US-I2-05): every role/kind literal used in a
TWE query's fact-predicate call must exist in spec/enum_registry.yml.

This is the guard that prevents v1's fatal bug (queries hardcoding role strings
like "attested_subject" / "attestation_use" that don't exist in the registry,
making the `where` clause unsatisfiable -> 0 results).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

SPEC = Path(__file__).resolve().parents[1] / "src" / "tee_audit" / "trustir" / "spec" / "enum_registry.yml"
GO_PACK = Path(__file__).resolve().parents[1] / "codeql" / "trustir" / "go"

_FACT_CALL = re.compile(
    r'is(?:ClaimField|AuthorityPoint|AuthoritySubject|TrustSource|TrustSink)\([^,]+,\s*"([^"]+)"\)'
)


def _enum_values() -> set[str]:
    reg = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    values: set[str] = set()
    for vals in reg.values():
        values.update(vals)
    return values


def test_go_query_role_kind_literals_are_in_enum_registry() -> None:
    enums = _enum_values()
    assert enums, "enum_registry loaded empty"
    checked = 0
    for ql in sorted(GO_PACK.glob("**/*.ql")):
        text = ql.read_text(encoding="utf-8")
        for role in _FACT_CALL.findall(text):
            checked += 1
            assert role in enums, (
                f"{ql.relative_to(GO_PACK)}: role/kind literal {role!r} is NOT in enum_registry.yml "
                "(this is the v1 bug that made queries return 0 results)"
            )
    assert checked > 0, "no fact-predicate role literals found — test wiring is off"
