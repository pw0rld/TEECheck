"""Stage 4: CodeQL Operations — database creation and scanning.

Python port of create_codeql_db.sh + run_baseline_scan.sh.
This is the ONLY stage that uses subprocess (exclusively for codeql CLI).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from tee_audit.contracts import Stage4Input, Stage4Output
from tee_audit.utils.codeql_check import find_codeql, validate_codeql

logger = logging.getLogger(__name__)


def _emit_summary(status: str, message: str, **kwargs: object) -> dict[str, object]:
    """Emit structured status summary (mirrors bash emit_summary pattern)."""
    summary = {"STATUS": status, "MESSAGE": message}
    summary.update(kwargs)
    return summary


def create_database(
    repo_path: Path,
    language: str,
    codeql_path: Path,
    artifact_root: Path,
    force: bool = False,
    build_command: str | None = None,
) -> tuple[Path, dict]:
    """Create a CodeQL database for the repository.

    Returns (db_path, summary_dict).
    """
    db_root = artifact_root / "codeql-dbs"
    result_root = artifact_root / "results"
    db_root.mkdir(parents=True, exist_ok=True)
    result_root.mkdir(parents=True, exist_ok=True)

    db_path = db_root / f"{repo_path.name}-{language}"

    # Check language is supported
    lang_check = subprocess.run(
        [str(codeql_path), "resolve", "languages"],
        capture_output=True, text=True, timeout=30,
    )
    supported = [line.split()[0] for line in lang_check.stdout.splitlines()]
    if language not in supported:
        msg = f"Language '{language}' not supported by CodeQL. Supported: {supported}"
        raise RuntimeError(msg)

    # Check existing database
    if db_path.exists() and not force:
        msg = f"Database already exists: {db_path}. Use force=True to overwrite."
        raise FileExistsError(msg)

    # Remove existing if force
    if db_path.exists() and force:
        import shutil
        shutil.rmtree(db_path)

    # Build args
    create_args = [str(codeql_path), "database", "create", str(db_path)]
    create_args += [f"--language={language}", f"--source-root={str(repo_path)}"]

    env = os.environ.copy()

    if language == "rust":
        cargo_home = str(artifact_root / "cargo-home")
        cargo_target = str(artifact_root / "cargo-target")
        os.makedirs(cargo_home, exist_ok=True)
        os.makedirs(cargo_target, exist_ok=True)
        env["CARGO_HOME"] = cargo_home
        env["CARGO_TARGET_DIR"] = cargo_target

        if build_command:
            create_args += ["--command", build_command]
        else:
            create_args.append("--build-mode=none")
        create_args.append(f"--extractor-option=rust.cargo_target_dir={cargo_target}")
    elif build_command:
        create_args += ["--command", build_command]

    logger.info("Creating CodeQL database: %s (%s)", db_path, language)
    result = subprocess.run(
        create_args, capture_output=True, text=True, env=env, timeout=1800,
    )

    if result.returncode != 0:
        summary = _emit_summary("failure", f"Database creation failed: {result.stderr[-500:]}", db_path=str(db_path))
        logger.error("CodeQL database creation failed: %s", result.stderr[-500:])
        raise RuntimeError(summary["MESSAGE"])

    if not (db_path / "codeql-database.yml").exists():
        msg = f"Database created but codeql-database.yml missing at {db_path}"
        raise RuntimeError(msg)

    summary = _emit_summary("success", "Database created", db_path=str(db_path), language=language)
    logger.info("CodeQL database created: %s", db_path)
    return db_path, summary


def run_baseline_scan(
    db_path: Path,
    suite_path: Path,
    codeql_path: Path,
    output_path: Path,
    force: bool = False,
) -> tuple[Path, int, dict]:
    """Run CodeQL baseline analysis, producing SARIF output.

    Returns (sarif_path, result_count, summary_dict).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not db_path.exists():
        msg = f"Database path does not exist: {db_path}"
        raise FileNotFoundError(msg)

    if not (db_path / "codeql-database.yml").exists():
        msg = f"Invalid database (missing codeql-database.yml): {db_path}"
        raise RuntimeError(msg)

    if output_path.exists() and not force:
        msg = f"Output already exists: {output_path}. Use force=True to overwrite."
        raise FileExistsError(msg)

    if output_path.exists() and force:
        output_path.unlink()

    logger.info("Running CodeQL baseline scan: %s", suite_path)
    result = subprocess.run(
        [
            str(codeql_path), "database", "analyze", str(db_path),
            str(suite_path),
            "--format=sarif-latest",
            f"--output={output_path}",
        ],
        capture_output=True, text=True, timeout=3600,
    )

    if result.returncode != 0:
        summary = _emit_summary("failure", f"Scan failed: {result.stderr[-500:]}")
        raise RuntimeError(summary["MESSAGE"])

    if not output_path.exists() or output_path.stat().st_size == 0:
        msg = "Scan completed but SARIF output is empty or missing"
        raise RuntimeError(msg)

    # Count results
    result_count = 0
    try:
        sarif_data = json.loads(output_path.read_text())
        result_count = sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))
    except (json.JSONDecodeError, OSError):
        logger.warning("Could not parse SARIF for result count")

    summary = _emit_summary("success", "Baseline scan completed", result_count=result_count, output=str(output_path))
    logger.info("CodeQL scan complete: %d results in %s", result_count, output_path)
    return output_path, result_count, summary


def run_codeql(input_data: Stage4Input, codeql_path: Path | None = None, artifact_root: Path | None = None) -> Stage4Output:
    """Run Stage 4: CodeQL database creation and baseline scan."""
    import tempfile

    logger.info("Stage 4: CodeQL operations for %s", input_data.repo_path)

    # Find and validate CodeQL
    if codeql_path is None:
        found = find_codeql()
        if found is None:
            msg = (
                "CodeQL not found in PATH. Install with: tee-audit setup codeql\n"
                "Or set TEE_AUDIT_CODEQL_PATH environment variable."
            )
            raise FileNotFoundError(msg)
        codeql_path = found

    codeql_path = validate_codeql(codeql_path)

    if artifact_root is None:
        artifact_root = Path(tempfile.mkdtemp(prefix="tee-audit-"))

    # Determine language (use first CodeQL-supported language from fingerprint context)
    language = "rust"  # Default for TEE projects; could be parameterized

    # Create database
    db_path, _ = create_database(
        input_data.repo_path, language, codeql_path, artifact_root,
    )

    # Determine query suite path
    suite = "codeql/rust-queries:codeql-suites/rust-security-extended.ql"
    # Check for project-specific queries
    project_queries = input_data.repo_path / "codeql-queries" / "tee-invariants.qls"
    if project_queries.exists():
        suite = str(project_queries)

    # Run scan
    sarif_path = artifact_root / "results" / "baseline.sarif"
    sarif_path, result_count, _ = run_baseline_scan(
        db_path, Path(suite), codeql_path, sarif_path,
    )

    logger.info("Stage 4 complete: %d results", result_count)
    return Stage4Output(db_path=db_path, sarif_path=sarif_path, result_count=result_count)
