"""CodeQL execution for the TrustIR pipeline (US-008 part B).

Builds (or reuses) a CodeQL database for a repo, materializes a per-run copy of
the language query pack with the generated facts injected, runs each TWE query,
and reduces SARIF output to the ``{twe_id, violation, count, locations, error}``
shape the solver consumes. Reuses tee-audit's ``utils.sarif``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tee_audit.trustir.binder.resolver import BindResult
from tee_audit.trustir.generator import generate_facts
from tee_audit.trustir.generator.query_plan_generator import query_module_for

# tee-audit/codeql/trustir — the self-contained per-language pack root.
PACK_ROOT = Path(__file__).resolve().parents[3] / "codeql" / "trustir"


def language_pack_dir(language: str) -> Path:
    """Return the query-pack directory for ``language`` (go/javascript/rust)."""
    p = PACK_ROOT / language
    if not p.is_dir():
        raise FileNotFoundError(f"no TrustIR CodeQL pack for language {language!r} at {p}")
    return p


def _toolchain_env() -> dict[str, str]:
    """PATH that includes the Go toolchain and cargo, so extractors can run."""
    env = os.environ.copy()
    extra = [str(Path.home() / "opt" / "go" / "bin"), str(Path.home() / ".cargo" / "bin")]
    env["PATH"] = ":".join([p for p in extra if Path(p).is_dir()] + [env.get("PATH", "")])
    return env


def _db_source_commit(repo_path: Path) -> str:
    """Current HEAD commit of ``repo_path`` ("" if not a git repo)."""
    try:
        from tee_audit.utils.repo import get_commit_hash
        return (get_commit_hash(repo_path) or "").strip()
    except Exception:  # noqa: BLE001 — non-git or git missing -> rebuild safely
        return ""


def _db_sidecar_path(db_path: Path) -> Path:
    """Sibling file recording the commit a cached DB was built from."""
    return db_path.parent / f"{db_path.name}.source-commit"


def _db_is_fresh(db_path: Path, commit: str) -> bool:
    """A cached DB is reusable only when its sidecar matches the current commit."""
    if not commit:
        return False
    sidecar = _db_sidecar_path(db_path)
    try:
        return sidecar.exists() and sidecar.read_text(encoding="utf-8").strip() == commit
    except OSError:
        return False


def _db_mark_commit(db_path: Path, commit: str) -> None:
    if commit:
        try:
            _db_sidecar_path(db_path).write_text(commit, encoding="utf-8")
        except OSError:
            pass


def build_or_get_db(
    repo_path: Path,
    language: str,
    codeql_path: Path,
    artifact_root: Path,
    force: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Create (source-only where possible) or reuse a CodeQL database.

    Go and JavaScript extraction is source-only (no build command); the Go
    extractor needs the Go toolchain on PATH (provided by :func:`_toolchain_env`).
    Rust needs a real build and is attempted best-effort with ``cargo build``.

    A DB is reused only when the checkout's current commit matches the
    ``.source-commit`` sidecar written at build time, so a checkout that moved to
    a new commit never silently reuses a stale DB.
    """
    repo_path = Path(repo_path).resolve()
    db_path = Path(artifact_root) / "codeql-db" / f"{repo_path.name}-{language}"
    commit = _db_source_commit(repo_path)
    if db_path.exists() and not force and _db_is_fresh(db_path, commit):
        return db_path, {"status": "reused", "db": str(db_path), "commit": commit}

    db_path.parent.mkdir(parents=True, exist_ok=True)
    env = _toolchain_env()

    # Source root for extraction. Most repos keep Cargo.toml at the repo root
    # (e.g. dcap-qvl). Some keep it in a sub-directory one level down (e.g.
    # automata-dcap-attestation keeps it under rust-crates/); the cargo extractor
    # requires the source root to be the directory containing Cargo.toml, so for
    # Rust we search one level down when the repo root has no Cargo.toml.
    source_root = repo_path
    summary: dict[str, Any] = {"status": "created", "language": language}
    if language == "rust":
        if not (repo_path / "Cargo.toml").is_file():
            cargo_dirs = sorted(p for p in repo_path.iterdir()
                                if p.is_dir() and (p / "Cargo.toml").is_file())
            if cargo_dirs:
                source_root = cargo_dirs[0]
                summary["source_root"] = str(source_root)

    cmd = [
        str(codeql_path), "database", "create", str(db_path),
        f"--language={language}",
        f"--source-root={source_root}",
        "--overwrite",
    ]
    if language == "rust":
        # Rust extraction requires a build to capture; best-effort.
        cmd += ["--command=cargo build"]

    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0 and language == "rust":
        # A workspace `cargo build` can fail when ONE workspace member has a
        # broken / unbuildable third-party dependency (e.g. automata-dcap-
        # attestation's apps/cli pulls boundless-market, which fails to compile
        # on this toolchain), even though the security-relevant core crates
        # build cleanly. Retry extraction targeting each workspace member
        # package individually; CodeQL's Rust extractor captures any crate
        # rustc compiles during the build command, so a per-member build still
        # extracts the buildable subset of the workspace.
        fallback = _rust_fallback_build(codeql_path, db_path, source_root, env)
        if fallback is not None:
            db_path2, summary2 = fallback
            summary2.setdefault("status", "created")
            summary2["language"] = language
            summary2["rust_fallback"] = True
            if "source_root" in summary:
                summary2["source_root"] = summary["source_root"]
            _db_mark_commit(db_path, commit)
            return db_path2, summary2
        raise RuntimeError(
            f"CodeQL database creation failed for {language}:\n"
            + (proc.stderr or proc.stdout or "")[-1200:]
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"CodeQL database creation failed for {language}:\n"
            + (proc.stderr or proc.stdout or "")[-1200:]
        )
    summary["tail"] = (proc.stderr or proc.stdout or "")[-300:]
    _db_mark_commit(db_path, commit)
    return db_path, summary


def _rust_workspace_members(source_root: Path, env: dict[str, str]) -> list[str]:
    """Return local workspace member package names from `cargo metadata`.

    Returns an empty list if ``source_root`` is a single package (no workspace)
    or ``cargo metadata`` is unavailable / fails. Dependencies are excluded —
    only path members of the workspace are returned, so the fallback never
    attempts to build a third-party crate directly.
    """
    import json

    try:
        proc = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version=1"],
            cwd=str(source_root), capture_output=True, text=True, env=env,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        doc = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return [p.get("name") for p in doc.get("packages", []) if p.get("name")]


def _rust_fallback_build(
    codeql_path: Path, db_path: Path, source_root: Path, env: dict[str, str]
) -> tuple[Path, dict[str, Any]] | None:
    """Retry Rust extraction building one workspace member at a time.

    Returns ``(db_path, summary)`` on success, or ``None`` if no member builds.
    The first member that builds produces a usable database (CodeQL's Rust
    extractor captures all crates compiled during the build command).
    """
    members = _rust_workspace_members(source_root, env)
    if not members:
        return None
    last_err = ""
    for pkg in members:
        cmd = [
            str(codeql_path), "database", "create", str(db_path),
            f"--language=rust",
            f"--source-root={source_root}",
            f"--command=cargo build -p {pkg}",
            "--overwrite",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if proc.returncode == 0:
            return db_path, {
                "tail": (proc.stderr or proc.stdout or "")[-300:],
                "rust_fallback_pkg": pkg,
            }
        last_err = (proc.stderr or proc.stdout or "")[-600:]
    if last_err:
        # Surface the last member's failure for diagnostics; callers raise if
        # this function returns None.
        pass
    return None


def _count_sarif_results(sarif_path: Path) -> tuple[int, list[dict[str, Any]]]:
    from tee_audit.utils.sarif import extract_results, parse_sarif

    doc = parse_sarif(sarif_path)
    results = extract_results(doc)
    locations = []
    for r in results:
        for loc in getattr(r, "locations", []) or []:
            phys = getattr(loc, "physical_location", None)
            artifact = getattr(phys, "artifact", None) if phys else None
            locations.append(
                {
                    "file": getattr(artifact, "uri", None) if artifact else None,
                    "line": getattr(phys, "line", None) if phys else None,
                }
            )
    return len(results), locations


def run_queries(
    db_path: Path,
    language: str,
    bind_result: BindResult,
    twe_ids: list[str],
    codeql_path: Path,
    workdir: Path,
) -> list[dict[str, Any]]:
    """Run each TWE query against ``db_path`` and return solver-ready result dicts.

    Steps: copy the language pack into ``workdir/pack``; overwrite
    ``common/GeneratedTrustFacts.qll`` with facts generated from ``bind_result``;
    run each query with ``codeql query run``; reduce SARIF to violation booleans.
    """
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = Path(db_path).resolve()
    pack = workdir / "pack"
    if pack.exists():
        shutil.rmtree(pack)
    shutil.copytree(language_pack_dir(language), pack)

    # Inject generated facts (FACTS ONLY) into the pack copy.
    facts_text = generate_facts(bind_result, language)
    (pack / "common" / "GeneratedTrustFacts.qll").write_text(facts_text, encoding="utf-8")

    codeql = str(codeql_path)
    out: list[dict[str, Any]] = []
    for twe in twe_ids:
        try:
            qrel = query_module_for(twe)
        except KeyError:
            out.append({"twe_id": twe, "violation": False, "error": "unknown_twe"})
            continue
        qfile = pack / qrel
        if not qfile.exists():
            out.append({"twe_id": twe, "violation": False, "error": "query_missing"})
            continue

        sarif_out = workdir / f"{twe}.sarif"
        cmd = [
            codeql, "database", "analyze", str(db_path),
            # --rerun: ALWAYS re-evaluate. Without it CodeQL replays a cached
            # BQRS from a prior run even when GeneratedTrustFacts.qll changed,
            # which makes stale findings masquerade as fresh results.
            "--rerun",
            "--format=sarifv2.1.0",
            f"--output={sarif_out}",
            str(qfile),
        ]
        proc = subprocess.run(cmd, cwd=str(pack), capture_output=True, text=True)
        if proc.returncode != 0:
            out.append(
                {
                    "twe_id": twe,
                    "violation": False,
                    "error": (proc.stderr or proc.stdout or "")[-800:],
                }
            )
            continue

        try:
            count, locations = _count_sarif_results(sarif_out)
        except Exception as exc:  # noqa: BLE001 - record and continue
            out.append({"twe_id": twe, "violation": False, "error": f"sarif_parse:{exc}"})
            continue

        out.append(
            {
                "twe_id": twe,
                "violation": count > 0,
                "count": count,
                "locations": locations,
            }
        )
    return out


def _parse_sarif_with_paths(sarif_path: Path) -> list[dict[str, Any]]:
    """Parse SARIF into per-result dicts with locations AND code-flow path steps."""
    import json

    doc = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    parsed: list[dict[str, Any]] = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = res.get("locations", [{}])[0]
            phys = loc.get("physicalLocation", {}) if loc else {}
            art = phys.get("artifactLocation", {}).get("uri")
            line = (phys.get("region", {}) or {}).get("startLine")
            # Collect ordered path steps from code flows (the source->sink trace).
            steps: list[dict[str, Any]] = []
            for cf in res.get("codeFlows", []) or []:
                for tf in cf.get("threadFlows", []) or []:
                    for fl in tf.get("locations", []) or []:
                        l = fl.get("location", {})
                        p = l.get("physicalLocation", {}) or {}
                        a = p.get("artifactLocation", {}).get("uri")
                        ln = (p.get("region", {}) or {}).get("startLine")
                        msg = (l.get("message", {}) or {}).get("text")
                        if a or ln:
                            steps.append({"file": a, "line": ln, "message": msg})
            parsed.append({"file": art, "line": line, "path_steps": steps,
                           "message": (res.get("message", {}) or {}).get("text")})
    return parsed


def run_all_queries(
    db_path: Path,
    language: str,
    resolved_set: Any,
    codeql_path: Path,
    workdir: Path,
    twe_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Iteration-2 runner: ONE pack copy + ONE facts module, run all queries once.

    ``resolved_set`` is a resolved ``TrustAnnotationSet``. Facts are generated
    with the name-based v2 generator (``annotation_facts.generate_facts``).
    Returns one dict per TWE: ``{twe_id, violation, count, results}`` where each
    result carries ``path_steps`` (the concrete source->sink trace).
    """
    from tee_audit.trustir.generator.annotation_facts import generate_facts
    from tee_audit.trustir.generator.query_plan_generator import all_twe_ids

    twe_ids = twe_ids or all_twe_ids()
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = Path(db_path).resolve()

    pack = workdir / "pack"
    if pack.exists():
        shutil.rmtree(pack)
    shutil.copytree(language_pack_dir(language), pack)
    (pack / "common" / "GeneratedTrustFacts.qll").write_text(
        generate_facts(resolved_set, language), encoding="utf-8"
    )

    codeql = str(codeql_path)
    out: list[dict[str, Any]] = []
    for twe in twe_ids:
        try:
            qrel = query_module_for(twe)
        except KeyError:
            out.append({"twe_id": twe, "violation": False, "error": "unknown_twe"})
            continue
        qfile = (pack / qrel).resolve()
        if not qfile.exists():
            out.append({"twe_id": twe, "violation": False, "error": "query_missing"})
            continue

        sarif_out = workdir / f"{twe}.sarif"
        proc = subprocess.run(
            [codeql, "database", "analyze", str(db_path),
             "--rerun",  # always re-evaluate; never replay a stale cached BQRS
             "--format=sarifv2.1.0", f"--output={sarif_out}", str(qfile)],
            cwd=str(pack), capture_output=True, text=True,
        )
        if proc.returncode != 0:
            out.append({"twe_id": twe, "violation": False,
                        "error": (proc.stderr or proc.stdout or "")[-800:]})
            continue
        try:
            results = _parse_sarif_with_paths(sarif_out)
        except Exception as exc:  # noqa: BLE001
            out.append({"twe_id": twe, "violation": False, "error": f"sarif_parse:{exc}"})
            continue
        out.append({"twe_id": twe, "violation": len(results) > 0,
                    "count": len(results), "results": results})
    return out


__all__ = ["PACK_ROOT", "language_pack_dir", "build_or_get_db",
           "run_queries", "run_all_queries", "_parse_sarif_with_paths"]
