"""Tests for the deterministic TrustIR binder (US-002).

Builds a tiny in-memory repo under tmp_path and exercises the resolution rules:
file_not_found, out_of_range, out_of_line, symbol_not_found, happy-path resolve,
and the zero-hallucination invariant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tee_audit.trustir.binder import (
    BindResult,
    Resolution,
    assert_no_hallucinated_resolutions,
    bind,
    bind_file,
)
from tee_audit.trustir.models import (
    AuthorityKind,
    AuthorityPoint,
    AuthoritySubject,
    AuthoritySubjectRole,
    ClaimField,
    ClaimFieldRole,
    ClaimProducer,
    EvidenceKind,
    EvidenceSpan,
    Guard,
    GuardKind,
    RepoInfo,
    Selector,
    TaxonomyFamily,
    TrustIR,
)
from tee_audit.trustir.binder.resolver import resolve_file


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

REGISTER_TS = """\
import { verifyReceipt } from "./receipt";
class Registry {
  // def verifyReceipt at line 3 region
  verifyReceipt(receipt: string) {
    return receipt.publicKey;
  }
  registerAgent(addr: string) {
    this.registry.registerAgent(addr, req.agentAddress);
  }
}
"""


def _write_repo(tmp_path: Path) -> Path:
    """Create a tiny repo with src/register.ts and return repo_root."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "register.ts").write_text(REGISTER_TS, encoding="utf-8")
    return repo


def _candidate(repo_root: Path) -> TrustIR:
    """A well-formed candidate that should fully resolve against the fixture repo."""
    return TrustIR(
        repo=RepoInfo(name="demo", root=str(repo_root)),
        candidate_id="cand-001",
        twe_id="TWE-BIND-001",
        taxonomy_family=TaxonomyFamily.BINDING,
        trust_context="receipt binding",
        evidence_spans=[
            EvidenceSpan(
                id="ev1",
                kind=EvidenceKind.CODE,
                file="src/register.ts",
                start_line=1,
                end_line=3,
                quote="...",
            )
        ],
        claim_producers=[
            ClaimProducer(
                id="prod1",
                kind="receipt_parser",
                selector=Selector(
                    file="src/register.ts",
                    qualified_name="Registry.verifyReceipt",
                    line=4,
                ),
                evidence_span_ids=["ev1"],
            )
        ],
        claim_fields=[
            ClaimField(
                id="cf1",
                producer_id="prod1",
                selector="receipt.publicKey",
                role=ClaimFieldRole.ATTESTED_PUBLIC_KEY,
            )
        ],
        authority_points=[
            AuthorityPoint(
                id="ap1",
                kind=AuthorityKind.REGISTRATION_ACCEPTANCE,
                selector=Selector(
                    file="src/register.ts", qualified_name="registry.registerAgent", line=7
                ),
                authority_subject=AuthoritySubject(
                    selector="req.agentAddress",
                    role=AuthoritySubjectRole.REGISTERED_AGENT,
                ),
            )
        ],
    )


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_happy_path_resolves_all(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    result = bind(_candidate(repo), repo)

    assert isinstance(result, BindResult)
    assert result.rejected == []
    summary = result.resolved.resolution_summary
    assert summary is not None
    assert summary["resolved"] >= 3  # producer + claim field + authority point (+ subject)
    assert summary["rejected"] == 0

    # Producer resolved.
    prod_res = result.resolutions["prod1"]
    assert prod_res.status == "resolved"
    assert prod_res.node["line_confirmed"] is True

    # Claim field resolved against the producer's file.
    assert result.resolutions["cf1"].status == "resolved"

    # Authority point resolved.
    assert result.resolutions["ap1"].status == "resolved"

    # Zero-hallucination invariant holds.
    assert_no_hallucinated_resolutions(result, repo)


# --------------------------------------------------------------------------- #
# file_not_found
# --------------------------------------------------------------------------- #


def test_file_not_found_rejected(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    cand.claim_producers[0].selector.file = "src/missing.ts"
    result = bind(cand, repo)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert "claim_producer" in by_kind
    assert by_kind["claim_producer"]["reason"] == "file_not_found"


# --------------------------------------------------------------------------- #
# out_of_range and out_of_line
# --------------------------------------------------------------------------- #


def test_out_of_range(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    # register.ts has 11 lines; claim line 999 is out of range.
    cand.claim_producers[0].selector.line = 999
    result = bind(cand, repo)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert by_kind["claim_producer"]["reason"] == "out_of_range"


def test_out_of_line(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    # verifyReceipt occurs at lines 1,3,4. Claiming line 8 (within 11-line file)
    # is in range but nearest occurrence is line 4 -> drift 4 > tolerance 2.
    cand.claim_producers[0].selector.line = 8
    result = bind(cand, repo, tolerance=2)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert by_kind["claim_producer"]["reason"] == "out_of_line"


def test_line_drift_within_tolerance_still_resolves(tmp_path: Path) -> None:
    """A claim line within tolerance of an occurrence resolves with line_drift note."""
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    # verifyReceipt is at line 4 in the def. Claiming line 5 -> drift 1 <= tol 2.
    cand.claim_producers[0].selector.line = 5
    result = bind(cand, repo, tolerance=2)

    prod_res = result.resolutions["prod1"]
    assert prod_res.status == "resolved"
    # Drift = claimed - matched = 5 - 4 = 1.
    assert prod_res.node["line_drift"] == 1


# --------------------------------------------------------------------------- #
# symbol_not_found
# --------------------------------------------------------------------------- #


def test_symbol_not_found(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    cand.claim_producers[0].selector.qualified_name = "Registry.doesNotExist"
    result = bind(cand, repo)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert by_kind["claim_producer"]["reason"] == "symbol_not_found"


def test_claim_field_not_found(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    cand.claim_fields[0].selector = "receipt.doesNotExistField"
    result = bind(cand, repo)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert by_kind["claim_field"]["reason"] == "field_not_found"


# --------------------------------------------------------------------------- #
# evidence span bounds
# --------------------------------------------------------------------------- #


def test_bad_span_rejected(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    cand.evidence_spans[0].end_line = 999  # exceeds 11-line file
    result = bind(cand, repo)

    by_kind = {r["kind"]: r for r in result.rejected}
    assert by_kind["evidence_span"]["reason"] == "bad_span"


# --------------------------------------------------------------------------- #
# Zero-hallucination invariant violation
# --------------------------------------------------------------------------- #


def test_hallucination_invariant_raises(tmp_path: Path) -> None:
    """Corrupt a resolved fact's backing file and assert the invariant raises."""
    repo = _write_repo(tmp_path)
    result = bind(_candidate(repo), repo)
    # Sanity: passes before corruption.
    assert_no_hallucinated_resolutions(result, repo)

    # Corrupt: point the resolved producer's file at a path that no longer exists.
    result.resolved.claim_producers[0].selector.file = "src/deleted.ts"

    with pytest.raises(AssertionError, match="hallucinated resolutions"):
        assert_no_hallucinated_resolutions(result, repo)


def test_hallucination_invariant_token_missing(tmp_path: Path) -> None:
    """Corrupt the backing file content so the token no longer occurs."""
    repo = _write_repo(tmp_path)
    result = bind(_candidate(repo), repo)

    # Overwrite register.ts to remove verifyReceipt entirely.
    (repo / "src" / "register.ts").write_text("// nothing here\n", encoding="utf-8")

    with pytest.raises(AssertionError, match="token"):
        assert_no_hallucinated_resolutions(result, repo)


# --------------------------------------------------------------------------- #
# Path-escape guard
# --------------------------------------------------------------------------- #


def test_resolve_file_rejects_escape(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    # Symlink-style escape via '..' should be normalized and rejected if outside.
    path, reason = resolve_file("../outside.ts", repo)
    assert path is None
    assert reason == "file_not_found"


# --------------------------------------------------------------------------- #
# bind_file entry point
# --------------------------------------------------------------------------- #


def test_bind_file_roundtrip(tmp_path: Path) -> None:
    repo = _write_repo(tmp_path)
    cand = _candidate(repo)
    # Write candidate to disk, then bind via bind_file.
    cand_path = tmp_path / "candidate.json"
    cand_path.write_text(cand.model_dump_json(indent=2), encoding="utf-8")

    result = bind_file(cand_path, repo)
    assert result.rejected == []
    assert isinstance(result, BindResult)
    assert isinstance(Resolution(fact_id="x", status="resolved"), Resolution)
