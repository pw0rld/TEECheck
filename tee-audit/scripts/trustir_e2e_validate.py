"""End-to-end iteration-3 validation harness (US-009 FP-kill + US-010 real path).

Runs the FULL iteration-3 chain on a real repo:
  fetch (run_fetch_queries) -> LLM classify (US-005 classify_repo) ->
  resolve_against_index (verify->reject) -> generate_facts -> run_all_queries
  (16 TWEs) -> solve_from_results -> triage_findings (write-only hint).

Then checks the success bar:
  US-009 (Go): the FLOW-001 signature-recovery FP is NOT `confirmed`.
  US-010: >=1 surviving real source->sink path (status in
          {violated_candidate, delegated, ...}) per language, else honest out_of_scope.

This uses stable primitives directly (not pipeline, which US-005 is wiring) so
it can validate before/after the pipeline integration. Run AFTER US-005 lands:
  PYTHONPATH=src .venv/bin/python scripts/trustir_e2e_validate.py go suave-geth
"""

from __future__ import annotations

import sys
from pathlib import Path

from tee_audit.trustir.codeql_runner import run_all_queries
from tee_audit.trustir.generator.annotation_facts import generate_facts
from tee_audit.trustir.generator.query_plan_generator import all_twe_ids
from tee_audit.trustir.resolver.index_resolver import resolve_against_index
from tee_audit.trustir.solver.result_solver import solve_from_results
from tee_audit.trustir.triage import triage_findings

CODEQL = Path("/home/payson/opt/codeql/codeql")
REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo_path(language: str, name: str) -> Path:
    guesses = [
        REPO_ROOT / "output" / f"{name}-audit" / name,
        REPO_ROOT / "output" / f"{name}-audit" / name.replace("-geth", ""),
    ]
    for g in guesses:
        if g.is_dir():
            return g
    raise FileNotFoundError(f"repo not found for {name}: {guesses}")


def _db_path(language: str, name: str) -> Path:
    # Existing DBs live under output/codeql-db/<name>-<lang>; fall back to artifact dir.
    cand = REPO_ROOT / "output" / "codeql-db" / f"{name}-{language}"
    if cand.is_dir():
        return cand
    art = REPO_ROOT / "output" / f"{name}-audit" / "artifact" / "codeql-db" / f"{name}-{language}"
    if art.is_dir():
        return art
    raise FileNotFoundError(f"no CodeQL DB for {name}-{language}")


def run(language: str, name: str, client=None) -> int:
    from tee_audit.trustir.extractor.enumerate_classify import classify_repo

    repo = _repo_path(language, name)
    db = _db_path(language, name)
    workdir = REPO_ROOT / "output" / f"{name}-audit" / "trustir"
    workdir.mkdir(parents=True, exist_ok=True)

    # 1+2. fetch + LLM classify (US-005). classify_repo returns (ann_set, enum_index).
    result = classify_repo(repo, language, CODEQL, workdir, client, repo_summary=name)
    if isinstance(result, tuple):
        ann_set, enum_index = result
    else:
        ann_set, enum_index = result, None

    # 3. resolve verify->reject against the authoritative index.
    if enum_index is not None:
        resolve_against_index(ann_set, enum_index, language)

    accepted = [a for a in ann_set.annotations
                if a.resolution_status and a.resolution_status.value in ("accepted", "repaired")]
    print(f"[{name}-{language}] {len(accepted)}/{len(ann_set.annotations)} annotations accepted")

    # 4+5. facts + run all 16 TWEs.
    results = run_all_queries(db, language, ann_set, CODEQL, workdir, all_twe_ids())
    # 6+7. solve + triage (no client -> deterministic heuristic fallback for triage).
    findings = solve_from_results(results)
    findings = triage_findings(findings, str(repo), client=client)

    # --- US-009: FLOW-001 must NOT be confirmed ---
    rc = 0
    for f in findings:
        twe = f.get("twe_id", "")
        status = f.get("status")
        hops = f.get("path_hops", 0)
        rule = f.get("applied_rule", "")
        hint = f.get("llm_vulnerable_hint")
        fired = f.get("status") not in (None,) and f.get("count", 0) > 0
        print(f"  {twe:24} status={status:20} hops={hops:4} rule={rule} hint={hint}")
        if twe.endswith("twe-flow-001") and status == "confirmed":
            print(f"  !! US-009 FAIL: {twe} is CONFIRMED (FP not killed)")
            rc = 1

    # --- US-010: >=1 surviving real path (non-trivial, non-out_of_scope) ---
    real = [f for f in findings
            if f.get("count", 0) > 0 and f.get("path_hops", 0) > 0
            and f.get("status") not in ("out_of_scope", "test_only", "unresolved", None)]
    if real:
        r = max(real, key=lambda f: f.get("path_hops", 0))
        print(f"  US-010: surviving real path -> {r['twe_id']} hops={r.get('path_hops')} status={r.get('status')}")
    else:
        print(f"  US-010: no surviving real path for {name}-{language} -> out_of_scope (honest)")

    # show the shortest representative path for the first fired finding
    for f in findings:
        if f.get("path"):
            print(f"  sample path ({f['twe_id']}):")
            for s in f["path"][:8]:
                print(f"    {s.get('file')}:{s.get('line')} {s.get('message') or ''}".rstrip())
            break
    return rc


if __name__ == "__main__":
    lang = sys.argv[1] if len(sys.argv) > 1 else "go"
    name = sys.argv[2] if len(sys.argv) > 2 else "suave-geth"
    # Default: no live LLM client (deterministic heuristic triage). Pass --llm to use GLM.
    client = None
    if "--llm" in sys.argv:
        from tee_audit.llm.client import LLMClient
        client = LLMClient.load() if hasattr(LLMClient, "load") else LLMClient()
    sys.exit(run(lang, name, client))
