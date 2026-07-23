"""Iteration-2 pipeline orchestration: extract -> resolve -> one facts module ->
run all queries once -> solve (with paths) -> report.

Supports a deterministic path (``--annotations`` JSON, no LLM) so the whole flow
is reproducible/testable, and an LLM path (dossier+zone extraction) otherwise.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tee_audit.trustir.annotations import TrustAnnotationSet
from tee_audit.trustir.reporter import (
    render_json, render_md, render_sarif, write_json, write_md, write_sarif,
)
from tee_audit.trustir.resolver import resolve_set
from tee_audit.trustir.solver.result_solver import solve_from_results


def _detect_language(repo_path: Path, override: str | None) -> str:
    if override:
        return override
    from tee_audit.utils.codeql_templates import detect_codeql_language

    return detect_codeql_language(repo_path)


def _find_existing_report(artifact_root: Path, name: str) -> Path | None:
    # Sibling legacy tee-audit report (the old audit lives next to trustir/).
    audit_results = Path(artifact_root) / f"{name}-audit" / "results"
    for cand in (audit_results / "report.md", audit_results / f"{name}.md"):
        if cand.is_file():
            return cand
    project_output = Path(__file__).resolve().parents[3] / "output" / "reports"
    for root in (Path(artifact_root) / "reports", project_output):
        if root.is_dir():
            cands = sorted(root.glob(f"*/{name}.md"), reverse=True)
            if cands:
                return cands[0]
    return None


def run_trustir(
    config: Any,
    repo_source: str,
    language: str | None = None,
    annotations_path: str | Path | None = None,
    run_codeql: bool = True,
    results_dir: str | Path | None = None,
    workdir: str | Path | None = None,
    twe_ids: list[str] | None = None,
    max_zones: int | None = None,
    max_workers: int = 1,
) -> dict[str, Any]:
    from tee_audit.utils.codeql_check import find_codeql, validate_codeql
    from tee_audit.utils.repo import get_commit_hash, resolve_repo_path

    artifact_root = Path(config.artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    name = Path(repo_source).name or "repo"
    # Per-repo audit folder: <artifact_root>/<name>-audit/ holds the checkout,
    # the CodeQL DB, the legacy tee-audit report, and the trustir/ subfolder.
    audit_dir = artifact_root / f"{name}-audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    repo_path = resolve_repo_path(repo_source, audit_dir=audit_dir)
    commit = get_commit_hash(repo_path)
    lang = _detect_language(repo_path, language)

    # Iteration-3 audit output is a versioned sibling of the legacy report, so
    # old-vs-new comparison is a one-level diff.
    out_dir = Path(results_dir) if results_dir else audit_dir / "trustir" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(workdir) if workdir else audit_dir / "trustir" / "codeql-work"
    work.mkdir(parents=True, exist_ok=True)

    # CodeQL DB at <audit_dir>/artifact/codeql-db/ — the same location the legacy
    # tee-audit run uses, so an existing DB is reused when the commit matches.
    db_artifact_root = audit_dir / "artifact"
    codeql_path = None
    db_path = None
    if run_codeql:
        f = find_codeql()
        codeql_path = validate_codeql(Path(f)) if f else None
        if codeql_path is not None:
            from tee_audit.trustir.codeql_runner import build_or_get_db

            db_path, _ = build_or_get_db(repo_path, lang, codeql_path, db_artifact_root)
        else:
            run_codeql = False

    # Annotations: deterministic fixture file, or iteration-3 LLM
    # enumerate-then-classify (CodeQL enumerates; LLM labels; resolver grounds).
    if annotations_path is not None:
        ann = TrustAnnotationSet.model_validate_json(Path(annotations_path).read_text(encoding="utf-8"))
        # Fixture path: ground with the iteration-2 name resolver for back-compat.
        resolved_out = resolve_set(ann, repo_path)
    else:
        from tee_audit.llm.client import create_client
        from tee_audit.trustir.extractor import classify_repo
        from tee_audit.trustir.resolver.index_resolver import resolve_against_index

        client = create_client(
            config.llm_provider, config.llm_api_key, config.llm_model, config.llm_base_url
        )
        # classify_repo runs the US-004 fetch queries + LLM classification and
        # returns the TrustAnnotationSet plus the EnumItemIndex that the
        # resolver grounds each annotation against (Decision-R).
        if not codeql_path:
            run_codeql = False
        if codeql_path is None:
            msg = "iteration-3 LLM path requires CodeQL (set --run-codeql / install CodeQL)."
            raise RuntimeError(msg)
        if db_path is None:
            from tee_audit.trustir.codeql_runner import build_or_get_db

            db_path, _ = build_or_get_db(repo_path, lang, codeql_path, db_artifact_root)
        ann, enum_index = classify_repo(
            repo_path=repo_path,
            language=lang,
            codeql_path=codeql_path,
            workdir=work,
            client=client,
            db_path=db_path,
            persist_dir=out_dir,
            max_workers=config.max_concurrent_llm_calls,
            scope=config.repo_scopes.get(name),
        )
        resolved = resolve_against_index(ann, enum_index, lang)
        # rejected = the resolver no longer mutates a separate list in
        # iteration-3; rejected annotations are inlined via resolution_status.
        rejected = [
            a.model_dump(mode="json")
            for a in resolved.annotations
            if a.resolution_status and a.resolution_status.value == "rejected"
        ]
        resolved_out = {
            "resolved": resolved,
            "rejected": rejected,
            "stats": {
                "total": len(resolved.annotations),
                "rejected": len(rejected),
                "accepted": sum(
                    1 for a in resolved.annotations
                    if a.resolution_status and a.resolution_status.value == "accepted"
                ),
            },
        }

    resolved = resolved_out["resolved"]
    (out_dir / "annotations.resolved.json").write_text(resolved.model_dump_json(indent=2), encoding="utf-8")
    (out_dir / "rejected.json").write_text(json.dumps(resolved_out["rejected"], indent=2), encoding="utf-8")

    # Run all queries once against one facts module.
    codeql_results: list[dict[str, Any]] = []
    if run_codeql and db_path and codeql_path:
        from tee_audit.trustir.codeql_runner import run_all_queries

        codeql_results = run_all_queries(db_path, lang, resolved, codeql_path, work, twe_ids)

    findings = solve_from_results(codeql_results)

    # US-008: post-hoc triage over findings. The solver owns status; triage
    # only writes an llm_vulnerable_hint signal (deterministic fallback when
    # no client). client is None on the deterministic fixture path.
    if findings:
        from tee_audit.trustir.triage import triage_findings

        triage_client = None
        if annotations_path is None:
            # reuse the LLM client created for classification
            try:
                triage_client = client  # noqa: F821 — defined in the LLM branch above
            except NameError:
                triage_client = None
        findings = triage_findings(findings, repo_path, client=triage_client)

    meta = {
        "repo": name, "repo_path": str(repo_path), "commit": commit, "language": lang,
        "pipeline": "trustir-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "resolved_stats": resolved_out["stats"],
    }
    write_json(render_json(findings, meta), out_dir / "findings.json")
    write_md(render_md(findings, meta), out_dir / "findings.md")
    write_sarif(render_sarif(findings, meta), out_dir / "findings.sarif")

    comparison_path = None
    existing_report = _find_existing_report(artifact_root, name)
    if existing_report:
        from tee_audit.trustir.comparison import build_comparison, parse_existing_report, write_comparison_md

        rep = parse_existing_report(existing_report)
        comparison_path = write_comparison_md(build_comparison(name, findings, rep), out_dir / "comparison.md")

    summary = {
        "repo": name, "language": lang, "pipeline": "trustir-v2",
        "resolved_stats": resolved_out["stats"],
        "codeql_run": run_codeql, "finding_count": len(findings),
        "statuses": sorted({f["status"] for f in findings}),
        "findings_with_path": sum(1 for f in findings if f.get("path")),
        "reports": {
            "json": str(out_dir / "findings.json"),
            "markdown": str(out_dir / "findings.md"),
            "sarif": str(out_dir / "findings.sarif"),
            "comparison": str(comparison_path) if comparison_path else None,
        },
    }
    (out_dir / "trustir_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


__all__ = ["run_trustir"]
