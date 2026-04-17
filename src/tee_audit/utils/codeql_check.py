"""CodeQL binary detection and setup."""

from __future__ import annotations

import logging
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

CODEQL_MIN_VERSION = "2.15.0"
DEFAULT_CODEQL_VERSION = "2.20.0"
CODEQL_RELEASES_URL = "https://github.com/github/codeql-cli-binaries/releases/download"


def find_codeql() -> Path | None:
    """Find CodeQL binary in PATH or configured location.

    Returns the path to the codeql binary, or None if not found.
    """
    # Check PATH
    codeql_in_path = shutil.which("codeql")
    if codeql_in_path:
        return Path(codeql_in_path)

    # Check configured location
    config_path = Path.home() / ".tee-audit" / "bin" / "codeql"
    if config_path.exists():
        return config_path

    # Check common locations
    for candidate in [
        Path.home() / ".codeql" / "codeql",
        Path("/usr/local/bin/codeql"),
    ]:
        if candidate.exists():
            return candidate

    return None


def check_codeql_version(codeql_path: Path) -> str:
    """Get CodeQL version string. Raises if codeql is not functional."""
    result = subprocess.run(
        [str(codeql_path), "version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        msg = f"CodeQL version check failed: {result.stderr}"
        raise RuntimeError(msg)

    # Output format: "CodeQL command-line tool version X.Y.Z"
    for line in result.stdout.splitlines():
        if "version" in line.lower():
            parts = line.split()
            for part in reversed(parts):
                if part[0].isdigit():
                    return part
    msg = f"Could not parse CodeQL version from output: {result.stdout}"
    raise RuntimeError(msg)


def validate_codeql(codeql_path: Path) -> Path:
    """Validate CodeQL is functional and meets minimum version.

    Returns the validated path. Raises if invalid.
    """
    if not codeql_path.exists():
        msg = f"CodeQL binary not found at: {codeql_path}"
        raise FileNotFoundError(msg)

    version = check_codeql_version(codeql_path)
    logger.info("CodeQL version: %s at %s", version, codeql_path)

    # Simple version comparison
    min_parts = [int(x) for x in CODEQL_MIN_VERSION.split(".")]
    cur_parts = [int(x) for x in version.split(".")[:3]]
    if cur_parts < min_parts:
        msg = f"CodeQL version {version} is below minimum {CODEQL_MIN_VERSION}"
        raise RuntimeError(msg)

    return codeql_path


def download_codeql(version: str | None = None) -> Path:
    """Download and install CodeQL CLI binary.

    Returns the path to the installed binary.
    """
    version = version or DEFAULT_CODEQL_VERSION
    install_dir = Path.home() / ".tee-audit" / "bin"
    install_dir.mkdir(parents=True, exist_ok=True)

    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        platform_str = "linux64"
    elif system == "darwin":
        platform_str = "macos64" if machine == "x86_64" else "arm64"
    else:
        msg = f"Unsupported platform: {system} {machine}"
        raise RuntimeError(msg)

    archive_name = f"codeql-{platform_str}.tar.gz"
    url = f"{CODEQL_RELEASES_URL}/v{version}/{archive_name}"

    logger.info("Downloading CodeQL v%s from %s", version, url)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / archive_name
        urllib.request.urlretrieve(url, archive_path)

        with tarfile.open(archive_path) as tar:
            # Prevent path traversal (CVE-2007-4559)
            for member in tar.getmembers():
                member_path = (install_dir / member.name).resolve()
                if not str(member_path).startswith(str(install_dir.resolve())):
                    msg = f"Tarfile path traversal attempt: {member.name}"
                    raise RuntimeError(msg)
            tar.extractall(install_dir)

    codeql_bin = install_dir / "codeql" / "codeql"
    if not codeql_bin.exists():
        # Try alternate layout
        codeql_bin = install_dir / "codeql"

    if codeql_bin.exists():
        codeql_bin.chmod(0o755)
        logger.info("CodeQL installed to %s", codeql_bin)
        return codeql_bin

    msg = f"CodeQL binary not found after extraction. Checked {codeql_bin}"
    raise RuntimeError(msg)
