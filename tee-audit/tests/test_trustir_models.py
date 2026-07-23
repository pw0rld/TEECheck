"""Tests for TrustIR models, loader, and validator (US-001)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tee_audit.trustir import load_trustir, validate_trustir, validate_trustir_file
from tee_audit.trustir.loader import dump_trustir, parse_trustir
from tee_audit.trustir.models import TrustIR


def _fixtures_dir() -> Path:
    """Self-contained TrustIR example candidates bundled inside tee-audit."""
    return Path(__file__).resolve().parent / "fixtures" / "trustir"


def _examples() -> dict[str, Path]:
    root = _fixtures_dir()
    return {
        "bind": root / "twe_bind_001_candidate.json",
        "guard": root / "twe_guard_001_candidate.json",
    }


def test_examples_load_without_error() -> None:
    for name, path in _examples().items():
        ir = load_trustir(path)
        assert isinstance(ir, TrustIR), f"{name} did not parse to TrustIR"
        assert ir.twe_id, f"{name} has empty twe_id"
        assert ir.taxonomy_family is not None


def test_examples_round_trip() -> None:
    for path in _examples().values():
        original = json.loads(path.read_text(encoding="utf-8"))
        ir = parse_trustir(original)
        dumped = json.loads(ir.model_dump_json(exclude_none=True))
        # Round-trip parse of the dump must succeed and preserve key identity fields.
        ir2 = parse_trustir(dumped)
        assert ir2.twe_id == ir.twe_id
        assert ir2.candidate_id == ir.candidate_id
        assert ir2.taxonomy_family == ir.taxonomy_family
        assert len(ir2.claim_fields) == len(ir.claim_fields)
        assert len(ir2.authority_points) == len(ir.authority_points)


def test_dump_and_reload(tmp_path: Path) -> None:
    ir = load_trustir(_examples()["bind"])
    out = tmp_path / "resolved.json"
    dump_trustir(ir, out)
    ir2 = load_trustir(out)
    assert ir2.twe_id == ir.twe_id


def test_validator_examples_ok_or_only_warnings() -> None:
    # The shipped examples are well-formed; at most soft warnings are allowed.
    for path in _examples().values():
        result = validate_trustir_file(path)
        assert result.ok, f"{path.name} reported errors: {[i.model_dump() for i in result.errors]}"


def test_malformed_bad_enum_role_rejected() -> None:
    data = json.loads(_examples()["bind"].read_text(encoding="utf-8"))
    data["claim_fields"][0]["role"] = "not_a_real_role"
    with pytest.raises(ValidationError):
        parse_trustir(data)


def test_malformed_missing_required_field_rejected() -> None:
    data = json.loads(_examples()["guard"].read_text(encoding="utf-8"))
    del data["twe_id"]
    with pytest.raises(ValidationError):
        parse_trustir(data)


def test_validator_detects_twe_family_mismatch() -> None:
    data = json.loads(_examples()["bind"].read_text(encoding="utf-8"))
    # twe_id is TWE-BIND-001 but claim family is Binding; flip taxonomy_family to Flow.
    data["taxonomy_family"] = "Flow"
    result = validate_trustir(data)
    assert not result.ok
    assert any(i.code == "coherence:twe_family" for i in result.errors)


def test_validator_detects_dangling_authority_point() -> None:
    data = json.loads(_examples()["bind"].read_text(encoding="utf-8"))
    data["required_obligations"][0]["authority_point_id"] = "DOES_NOT_EXIST"
    result = validate_trustir(data)
    assert not result.ok
    assert any(i.code == "dangling:authority_point" for i in result.errors)


def test_deep_copy_independent() -> None:
    ir = load_trustir(_examples()["guard"])
    ir2 = copy.deepcopy(ir)
    ir2.claim_fields[0].id = "CHANGED"
    assert ir.claim_fields[0].id != "CHANGED"
