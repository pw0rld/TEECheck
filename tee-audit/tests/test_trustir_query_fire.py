"""Integration test: redesigned queries FIRE on a real Go DB with name-based facts.

This is the gate v1 failed: queries must produce results (a real path) when given
a correctly-resolved annotation set. Requires the CodeQL CLI + Go toolchain; skips
gracefully if absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from tee_audit.trustir.annotations import AnnotationKind, TrustAnnotation, TrustAnnotationSet
from tee_audit.trustir.generator.annotation_facts import generate_facts
from tee_audit.trustir.resolver import resolve_set

_FIXTURE_GO = """package main

func verifyQuote() string { return "attested" }

func registerAgent(agentAddr string) { _ = agentAddr }

func handle(input string) {
\tkey := verifyQuote()
\tregisterAgent("0xabc")
\tderiveKey(input)
\t_ = key
}

func deriveKey(seed string) {}
"""


def _codeql() -> Path | None:
    try:
        from tee_audit.utils.codeql_check import find_codeql, validate_codeql

        f = find_codeql()
        return validate_codeql(Path(f)) if f else None
    except Exception:  # noqa: BLE001
        return None


def _go_available() -> bool:
    return bool(shutil.which("go")) or (Path.home() / "opt" / "go" / "bin" / "go").exists()


pytestmark = pytest.mark.skipif(
    _codeql() is None or not _go_available(),
    reason="CodeQL CLI or Go toolchain not available",
)


def _annotations() -> TrustAnnotationSet:
    return TrustAnnotationSet(
        repo="fix",
        annotations=[
            TrustAnnotation(id="V", kind=AnnotationKind.VERIFIER, role="attestation_verifier",
                            name="verifyQuote", file="main.go", line=3, claim_field_role="attested_public_key"),
            TrustAnnotation(id="A", kind=AnnotationKind.AUTHORITY, role="registration_acceptance",
                            name="registerAgent", file="main.go", line=5,
                            subject_param="agentAddr", subject_role="registered_agent"),
            TrustAnnotation(id="S", kind=AnnotationKind.SOURCE, role="host_input",
                            name="handle", param="input", file="main.go", line=7),
            TrustAnnotation(id="K", kind=AnnotationKind.SINK, role="key_derivation_input",
                            name="deriveKey", file="main.go", line=11),
        ],
    )


def _run_query(db: Path, pack: Path, query_rel: str, codeql: Path) -> int:
    sarif = pack.parent / (Path(query_rel).stem + ".sarif")
    qfile = (pack / query_rel).resolve()
    proc = subprocess.run(
        [str(codeql), "database", "analyze", str(db),
         "--rerun", "--format=sarifv2.1.0", f"--output={sarif}", str(qfile)],
        cwd=str(pack), capture_output=True, text=True,
    )
    assert proc.returncode == 0, (proc.stderr or proc.stdout)[-1000:]
    import json
    doc = json.loads(sarif.read_text())
    return sum(len(run.get("results", [])) for run in doc.get("runs", []))


def test_queries_fire_on_real_db(tmp_path: Path) -> None:
    codeql = _codeql()
    from tee_audit.trustir.codeql_runner import build_or_get_db

    # 1. fixture repo + DB
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "main.go").write_text(_FIXTURE_GO, encoding="utf-8")
    db, _ = build_or_get_db(repo, "go", codeql, tmp_path)

    # 2. resolve annotations against the repo, generate name-based facts
    ann_set = _annotations()
    resolve_set(ann_set, repo, tolerance=3)
    accepted = [a for a in ann_set.annotations if a.resolution_status.value in ("accepted", "repaired")]
    assert accepted, "annotations should resolve against the fixture"
    facts = generate_facts(ann_set, "go")
    assert "verifyQuote" in facts and "registerAgent" in facts
    assert "authoritySubjectOf" in facts and "none()" not in facts.split("predicate authoritySubjectOf")[1].split("}")[0]

    # 3. inject facts into a pack copy
    src_pack = Path(__file__).resolve().parents[1] / "codeql" / "trustir" / "go"
    pack = tmp_path / "pack"
    shutil.copytree(src_pack, pack)
    (pack / "common" / "GeneratedTrustFacts.qll").write_text(facts, encoding="utf-8")

    # 4. run the redesigned queries — both must FIRE (>=1 result)
    n_bind = _run_query(db, pack, "binding/MissingSubjectBinding.ql", codeql)
    n_flow = _run_query(db, pack, "flow/HostToEnclaveSecurityDecision.ql", codeql)
    assert n_bind >= 1, "TWE-BIND-001 should fire: registered_agent not bound to attested key"
    assert n_flow >= 1, "TWE-FLOW-001 should fire: host input reaches deriveKey sink"
