"""Fixture tests for the 4 priority TWEs (US-012).

Proves the deterministic bind -> solve core classifies vulnerable vs guarded
cases correctly for GUARD-001, BIND-001, CONFIG-001, LEAK-001. CodeQL results are
simulated (the query "fired" with violation=True); suppressors/coverage drive the
guarded outcomes exactly as the solver rules specify.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tee_audit.trustir.models import TaxonomyFamily, TrustIR
from tee_audit.trustir.runner import resolve_and_solve


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "x.go").write_text(
        "package main\n\nfunc doAction() {\n\t// authority point\n}\n", encoding="utf-8"
    )
    return repo


def _ir(twe_id: str, family: TaxonomyFamily, suppressors: list[dict]) -> TrustIR:
    return TrustIR.model_validate(
        {
            "schema_version": "1.0",
            "repo": {"name": "x", "root": "/repo"},
            "candidate_id": "C1",
            "twe_id": twe_id,
            "taxonomy_family": family.value,
            "trust_context": "fixture",
            "authority_points": [
                {
                    "id": "AP1",
                    "kind": "registration_acceptance",
                    "selector": {"language": "go", "file": "src/x.go",
                                 "qualified_name": "doAction", "line": 3},
                }
            ],
            "required_obligations": [
                {"id": "O1", "twe_id": twe_id, "family": family.value,
                 "authority_point_id": "AP1"}
            ],
            "suppressors": suppressors,
        }
    )


def _qr(twe_id: str) -> dict:
    return {"twe_id": twe_id, "authority_point_id": "AP1", "violation": True}


# (twe_id, family, suppressors, coverage, expected_status)
CASES = [
    pytest.param("TWE-BIND-001", TaxonomyFamily.BINDING, [], {}, "confirmed",
                 id="bind-vulnerable"),
    pytest.param("TWE-BIND-001", TaxonomyFamily.BINDING, [{"kind": "registry_enforces"}], {},
                 "guarded_elsewhere", id="bind-guarded"),
    pytest.param("TWE-GUARD-001", TaxonomyFamily.GUARD, [], {}, "confirmed",
                 id="guard-vulnerable"),
    pytest.param("TWE-GUARD-001", TaxonomyFamily.GUARD, [{"kind": "checked_inside_verifier"}], {},
                 "delegated", id="guard-guarded"),
    pytest.param("TWE-CONFIG-001", TaxonomyFamily.CONFIG, [],
                 {"production_value_unknown": True}, "configuration_dependent",
                 id="config-vulnerable"),
    pytest.param("TWE-CONFIG-001", TaxonomyFamily.CONFIG, [{"kind": "test_only_path"}], {},
                 "test_only", id="config-guarded"),
    pytest.param("TWE-LEAK-001", TaxonomyFamily.LEAKAGE, [], {}, "confirmed",
                 id="leak-vulnerable"),
    pytest.param("TWE-LEAK-001", TaxonomyFamily.LEAKAGE, [{"kind": "guarded_elsewhere"}], {},
                 "guarded_elsewhere", id="leak-guarded"),
]


@pytest.mark.parametrize("twe_id,family,suppressors,coverage,expected", CASES)
def test_priority_twe_fixture(
    tmp_path: Path,
    twe_id: str,
    family: TaxonomyFamily,
    suppressors: list[dict],
    coverage: dict,
    expected: str,
) -> None:
    repo = _repo(tmp_path)
    out = resolve_and_solve(_ir(twe_id, family, suppressors), repo, [_qr(twe_id)], coverage)
    assert len(out["findings"]) == 1
    assert out["findings"][0]["status"] == expected, out["findings"]
