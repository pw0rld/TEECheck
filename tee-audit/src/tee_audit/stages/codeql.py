"""Stage 4: CodeQL Operations — database creation and scanning.

Python port of create_codeql_db.sh + run_baseline_scan.sh.
This is the ONLY stage that uses subprocess (exclusively for codeql CLI).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from tee_audit.contracts import Stage4Input, Stage4Output
from tee_audit.utils.codeql_check import find_codeql, validate_codeql
from tee_audit.utils.codeql_templates import detect_codeql_language, generate_codeql_queries

if TYPE_CHECKING:
    from tee_audit.llm.client import LLMClient

logger = logging.getLogger(__name__)


def _emit_summary(status: str, message: str, **kwargs: object) -> dict[str, object]:
    """Emit structured status summary (mirrors bash emit_summary pattern)."""
    summary = {"STATUS": status, "MESSAGE": message}
    summary.update(kwargs)
    return summary


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill an entire process tree (parent + all children) via SIGKILL."""
    import shutil

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


class _ProgressLogger:
    """Background thread that logs progress during long CodeQL operations."""

    def __init__(self, operation: str, interval: int = 60):
        self._operation = operation
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        elapsed = 0
        while not self._stop.wait(self._interval):
            elapsed += self._interval
            logger.info("CodeQL %s still running (%ds elapsed)...", self._operation, elapsed)


def _run_subprocess_with_cleanup(
    args: list[str],
    env: dict[str, str] | None = None,
    timeout: int = 1800,
    progress_label: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess in its own process group with guaranteed cleanup.

    Uses a new process group so that on timeout or interrupt, the entire
    CodeQL process tree (java, extractors, workers) is killed, preventing
    zombie processes.
    """
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,  # new process group for cleanup
    )

    progress = _ProgressLogger(progress_label or args[0])
    progress.start()

    killed = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Process timed out after %ds, killing process tree: %s", timeout, args[0])
        _kill_process_tree(proc)
        stdout, stderr = proc.communicate(timeout=30)
        killed = True
    except KeyboardInterrupt:
        logger.warning("Interrupted, killing process tree: %s", args[0])
        _kill_process_tree(proc)
        stdout, stderr = proc.communicate(timeout=30)
        killed = True
    finally:
        progress.stop()

    returncode = proc.returncode if not killed else -signal.SIGKILL

    return subprocess.CompletedProcess(
        args=args, returncode=returncode,
        stdout=stdout, stderr=stderr,
    )


def _is_valid_database(db_path: Path) -> bool:
    """Check if a CodeQL database directory is valid and usable."""
    if not db_path.is_dir():
        return False
    if not (db_path / "codeql-database.yml").exists():
        return False
    if not any(db_path.iterdir()):
        return False
    return True


def install_query_dependencies(codeql_path: Path, query_pack_dir: Path) -> None:
    """Run 'codeql pack install' to resolve query pack dependencies.

    This is required before running custom queries that depend on
    codeql/rust-all or other standard library packs.
    """
    qlpack_file = query_pack_dir / "qlpack.yml"
    if not qlpack_file.exists():
        logger.warning("No qlpack.yml found at %s, skipping pack install", query_pack_dir)
        return

    logger.info("Installing query pack dependencies: %s", query_pack_dir)
    result = _run_subprocess_with_cleanup(
        [str(codeql_path), "pack", "install", str(query_pack_dir)],
        timeout=300,
        progress_label="pack install",
    )

    if result.returncode != 0:
        logger.warning(
            "codeql pack install failed (non-fatal): %s",
            result.stderr[-500:] if result.stderr else "no stderr",
        )
    else:
        logger.info("Query pack dependencies installed successfully")


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
    db_root = artifact_root / "codeql-db"
    db_root.mkdir(parents=True, exist_ok=True)

    db_path = db_root / f"{repo_path.name}-{language}"

    # Check language is supported
    lang_check = _run_subprocess_with_cleanup(
        [str(codeql_path), "resolve", "languages"],
        timeout=30,
    )
    supported = [line.split()[0] for line in lang_check.stdout.splitlines()]
    if language not in supported:
        msg = f"Language '{language}' not supported by CodeQL. Supported: {supported}"
        raise RuntimeError(msg)

    # Reuse existing valid database
    if _is_valid_database(db_path) and not force:
        logger.info("Reusing existing CodeQL database: %s", db_path)
        summary = _emit_summary("success", "Reused existing database", db_path=str(db_path), language=language)
        return db_path, summary

    # Remove existing if invalid or forced
    if db_path.exists():
        shutil.rmtree(db_path, ignore_errors=True)

    # Build args
    create_args = [str(codeql_path), "database", "create", str(db_path)]
    create_args += [f"--language={language}", f"--source-root={str(repo_path)}"]

    env = os.environ.copy()

    # Check for Go (needed for Go CodeQL database creation)
    if language == "go" and not shutil.which("go"):
        logger.warning(
            "Go not found in PATH. Install Go or add it to PATH.  "
            "Go projects will fail CodeQL database creation."
        )

    # Check for Intel SGX SDK (needed for C++ enclave projects)
    # Users should run: source <sgx_sdk_install_path>/environment
    # This sets SGX_SDK, PATH, LD_LIBRARY_PATH, PKG_CONFIG_PATH, etc.
    if "SGX_SDK" not in env and language in ("cpp", "c"):
        logger.warning(
            "Intel SGX SDK not configured. Run: source <sdk_path>/sgxsdk/environment  "
            "C++ enclave projects may fail CodeQL database creation."
        )

    # For C/C++ projects, set SGX_MODE default if not already set
    if language in ("cpp", "c"):
        env.setdefault("SGX_MODE", "SIM")
        # PDO-style projects need PDO_SOURCE_ROOT pointing at the repo root
        if (repo_path / "build" / "Makefile").exists():
            env.setdefault("PDO_SOURCE_ROOT", str(repo_path))

    if language == "rust":
        cargo_home = str((artifact_root / "cargo-home").resolve())
        cargo_target = str((artifact_root / "cargo-target").resolve())
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

    # Rust extraction on large workspaces can take >30 min
    db_timeout = 3600 if language == "rust" else 1800

    logger.info("Creating CodeQL database: %s (%s)", db_path, language)
    result = _run_subprocess_with_cleanup(
        create_args, env=env, timeout=db_timeout,
        progress_label=f"database create ({language})",
    )

    if result.returncode != 0:
        # Clean up partial database on failure
        shutil.rmtree(db_path, ignore_errors=True)
        stderr_tail = (result.stderr or "")[-1000:]
        logger.error("CodeQL database creation failed. stderr:\n%s", stderr_tail)
        summary = _emit_summary("failure", f"Database creation failed: {stderr_tail[-500:]}", db_path=str(db_path))
        raise RuntimeError(summary["MESSAGE"])

    if not _is_valid_database(db_path):
        msg = f"Database created but invalid at {db_path}"
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
    search_paths: list[str] | None = None,
) -> tuple[Path, int, dict]:
    """Run CodeQL baseline analysis, producing SARIF output.

    Returns (sarif_path, result_count, summary_dict).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not _is_valid_database(db_path):
        msg = f"Database path does not exist or is invalid: {db_path}"
        raise FileNotFoundError(msg)

    # Reuse existing SARIF output (with staleness check)
    if output_path.exists() and output_path.stat().st_size > 0 and not force:
        sarif_mtime = output_path.stat().st_mtime
        db_mtime = db_path.stat().st_mtime if db_path.exists() else 0
        suite_mtime = suite_path.stat().st_mtime if suite_path.exists() else 0
        if sarif_mtime >= db_mtime and sarif_mtime >= suite_mtime:
            logger.info("Reusing existing SARIF output: %s", output_path)
            result_count = 0
            try:
                sarif_data = json.loads(output_path.read_text())
                result_count = sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))
            except (json.JSONDecodeError, OSError):
                pass
            summary = _emit_summary("success", "Reused existing scan results", result_count=result_count, output=str(output_path))
            return output_path, result_count, summary
        else:
            logger.info("SARIF is stale (older than db or suite), re-running scan")

    if output_path.exists() and force:
        output_path.unlink()

    logger.info("Running CodeQL baseline scan: %s", suite_path)

    scan_args = [
        str(codeql_path), "database", "analyze", str(db_path),
        str(suite_path),
        "--format=sarif-latest",
        f"--output={output_path}",
    ]
    for sp in (search_paths or []):
        scan_args += ["--search-path", sp]
        scan_args += ["--additional-packs", sp]

    result = _run_subprocess_with_cleanup(
        scan_args, timeout=3600,
        progress_label=f"baseline scan ({suite_path.name if suite_path.exists() else suite_path})",
    )

    if result.returncode != 0:
        stderr_tail = (result.stderr or "")[-1000:]
        logger.error("CodeQL scan failed. stderr:\n%s", stderr_tail)
        summary = _emit_summary("failure", f"Scan failed: {stderr_tail[-500:]}")
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


def run_codeql(
    input_data: Stage4Input,
    codeql_path: Path | None = None,
    artifact_root: Path | None = None,
    client: "LLMClient | None" = None,
    temperature: float = 0.0,
) -> Stage4Output:
    """Run Stage 4: CodeQL database creation and baseline scan.

    Optionally generates project-specific queries via LLM before scanning.
    """
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

    # Detect language from repo
    language = detect_codeql_language(input_data.repo_path)

    # Create database (reuses existing if valid)
    db_path, _ = create_database(
        input_data.repo_path, language, codeql_path, artifact_root,
    )

    # Build search paths: CodeQL distribution qlpacks + user packages
    codeql_root = codeql_path.parent.parent
    search_paths = [str(codeql_root / "qlpacks")]
    user_packs = Path.home() / ".codeql" / "packages"
    if user_packs.exists():
        search_paths.append(str(user_packs))

    # Run scan — delete stale SARIF to ensure fresh results
    sarif_path = artifact_root / "results" / "baseline.sarif"
    if sarif_path.exists():
        sarif_path.unlink()
        logger.info("Deleted stale SARIF before running new queries")

    # Try custom queries first, fall back to built-in suite
    suites_to_try: list[tuple[str, str]] = []

    # Step 1: LLM generates queries from taint specs
    language = detect_codeql_language(input_data.repo_path)
    if input_data.invariants and client:
        generated_pack = generate_codeql_queries(
            invariants=input_data.invariants,
            repo_path=input_data.repo_path,
            language=language,
            client=client,
            temperature=temperature,
            codeql_path=codeql_path,
            manifest_entry_points=input_data.manifest_entry_points,
        )
        if generated_pack is None:
            raise RuntimeError(
                "LLM CodeQL query generation failed — cannot proceed with "
                "generic queries. Check LLM provider connectivity and retry."
            )
        install_query_dependencies(codeql_path, generated_pack)
        suites_to_try.append(("LLM-generated queries",
            str(generated_pack / "tee-generated.qls")))
        logger.info("Added LLM-generated queries from %s", generated_pack)

    # Step 2: Project-specific queries (if repo has custom queries)
    project_queries = input_data.repo_path / "codeql-queries" / "tee-invariants.qls"
    if project_queries.exists():
        suites_to_try.append(("project-specific", str(project_queries)))

    # Built-in security suite (language-specific)
    built_in_suites = {
        "rust": "codeql/rust-queries:codeql-suites/rust-security-extended.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    }
    built_in_suite = built_in_suites.get(language, built_in_suites["rust"])
    suites_to_try.append(("built-in security", built_in_suite))

    last_error: str = ""
    for suite_label, suite_path in suites_to_try:
        try:
            sarif_path, result_count, _ = run_baseline_scan(
                db_path, Path(suite_path), codeql_path, sarif_path,
                search_paths=search_paths,
            )
            logger.info("Stage 4 complete using %s suite: %d results", suite_label, result_count)
            return Stage4Output(db_path=db_path, sarif_path=sarif_path, result_count=result_count)
        except RuntimeError as e:
            last_error = str(e)
            logger.warning("Query suite '%s' failed: %s", suite_label, last_error[:200])
            # Clean up failed SARIF so next suite can try
            if sarif_path.exists():
                sarif_path.unlink()
            continue

    raise RuntimeError(f"All CodeQL query suites failed. Last error: {last_error[:300]}")
