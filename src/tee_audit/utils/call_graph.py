"""Deterministic file discovery — walks code references to find related files.

Extends the proven _resolve_code_ref() pattern from report_review.py.
Runs before the LLM call in Stage 5b to ground analysis in real code paths.

Also provides trust zone classification and semantic call chain tracing
for reducing false positives in TEE audit reports.
"""

from __future__ import annotations

import heapq
import logging
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Trust Zone Classification
# ---------------------------------------------------------------------------

class TrustZone(str, Enum):
    """Classification of where code executes relative to TEE boundaries."""

    TRUSTED = "trusted"        # Runs inside the enclave/TEE
    UNTRUSTED = "untrusted"    # Runs on the host/outside the TEE
    MIXED = "mixed"            # Contains both trusted and untrusted interfaces
    UNKNOWN = "unknown"        # Cannot determine from available evidence


class ZoneMap(BaseModel):
    """Mapping of files to their trust zones."""

    zones: dict[str, TrustZone] = {}  # relative_path -> zone
    edl_files: list[str] = []          # EDL interface definitions
    entry_points: dict[str, list[str]] = {}  # file -> [ecall/ocall names]
    zone_source: dict[str, str] = {}   # relative_path -> "heuristic" | "manifest" | "llm_inferred"
    llm_reasoning: dict[str, str] = {}  # relative_path -> LLM explanation (only for llm_inferred)
    project_role: str = ""              # "enclave_only" | "host_only" | "mixed" | ""
    project_role_reasoning: str = ""    # LLM explanation for the project role


class CallChainHop(BaseModel):
    """One hop in a traced call chain."""

    file: str
    function: str = ""
    zone: TrustZone = TrustZone.UNKNOWN
    line: int | None = None
    crosses_boundary: bool = False  # True if this hop crosses trust zones


class CallChain(BaseModel):
    """A traced invocation chain with zone annotations."""

    hops: list[CallChainHop] = []
    zones_crossed: int = 0
    depth: int = 0
    has_end_to_end_evidence: bool = False


class CallSite(BaseModel):
    """A concrete function call site (caller → callee)."""

    caller_function: str
    callee_name: str
    callee_module: str = ""  # e.g. "ChainStorage" from "ChainStorage::from_pairs"
    line: int
    file: str


class FunctionDef(BaseModel):
    """A function definition found in the codebase."""

    name: str
    file: str
    line: int
    is_pub: bool = False
    impl_target: str = ""  # e.g. "RpcService<Platform>"


class EntryPoint(BaseModel):
    """A trust boundary entry point (ECALL, RPC handler, etc)."""

    file: str
    function: str
    entry_type: str  # "ecall", "ocall", "rpc_handler", "http_handler"
    zone: TrustZone
    line: int | None = None


class InvocationChain(BaseModel):
    """A backward-traced invocation chain from sink to entry point."""

    entry_point: EntryPoint | None = None
    hops: list[CallSite] = []
    sink_file: str = ""
    sink_function: str = ""
    zones_crossed: int = 0
    complete: bool = False  # True if chain reaches a known entry point
    confidence: str = "heuristic"  # "confirmed" | "heuristic" | "incomplete" | "no_chain"


# Path patterns strongly indicating trusted (enclave) code
_TRUSTED_PATH_PATTERNS = [
    re.compile(r"(?:^|/)enclave/(?:src|core)/", re.IGNORECASE),
    re.compile(r"(?:^|/)trusted/", re.IGNORECASE),
    re.compile(r"(?:^|/)tee/(?:src|core)/", re.IGNORECASE),
    re.compile(r"(?:^|/)sgx/(?:enclave|trusted)/", re.IGNORECASE),
    re.compile(r"(?:^|/)pal/(?:src|core)/", re.IGNORECASE),
    re.compile(r"(?:^|/)worker/(?:src|core)/", re.IGNORECASE),
    re.compile(r"/ecall", re.IGNORECASE),
    re.compile(r"/trusted_?", re.IGNORECASE),
    re.compile(r"_enclave\.(rs|c|cpp|h)$", re.IGNORECASE),
]

# Path patterns strongly indicating untrusted (host) code
_UNTRUSTED_PATH_PATTERNS = [
    re.compile(r"(?:^|/)host/", re.IGNORECASE),
    re.compile(r"(?:^|/)untrusted/", re.IGNORECASE),
    re.compile(r"(?:^|/)app/(?!src)", re.IGNORECASE),
    re.compile(r"(?:^|/)server/", re.IGNORECASE),
    re.compile(r"(?:^|/)cli/", re.IGNORECASE),
    re.compile(r"(?:^|/)client/", re.IGNORECASE),
    re.compile(r"(?:^|/)bin/", re.IGNORECASE),
    re.compile(r"(?:^|/)service/", re.IGNORECASE),
    re.compile(r"/ocall", re.IGNORECASE),
    re.compile(r"_host\.(rs|c|cpp|h)$", re.IGNORECASE),
    re.compile(r"_untrusted\.(rs|c|cpp|h)$", re.IGNORECASE),
]

# Content patterns indicating the file runs inside the enclave
_TRUSTED_CONTENT_PATTERNS = [
    re.compile(r"#\[no_mangle]\s*(?:pub\s+)?extern\s+\"C\"\s+fn", re.MULTILINE),  # Rust ECALL
    re.compile(r"sgx_trts::", re.IGNORECASE),          # SGX trusted runtime
    re.compile(r"sgx_tstd::", re.IGNORECASE),          # SGX trusted std
    re.compile(r"sgx_tcrypto::", re.IGNORECASE),       # SGX trusted crypto
    re.compile(r"sgx_tse::", re.IGNORECASE),           # SGX trusted sealing
    re.compile(r"enclave\s*\(", re.IGNORECASE),        # Enclave entry
    re.compile(r"ECALL", re.IGNORECASE),
    re.compile(r"from_tee", re.IGNORECASE),
    re.compile(r"in_enclave", re.IGNORECASE),
    re.compile(r"trusted_module", re.IGNORECASE),
    # Gramine patterns
    re.compile(r"pal_gramine", re.IGNORECASE),
    re.compile(r"GraminePlatform", re.IGNORECASE),
    re.compile(r"is_gramine", re.IGNORECASE),
    re.compile(r"gramine::", re.IGNORECASE),
]

# Content patterns indicating the file runs outside the enclave (host)
_UNTRUSTED_CONTENT_PATTERNS = [
    re.compile(r"sgx_urts::", re.IGNORECASE),          # SGX untrusted runtime
    re.compile(r"sgx_uae::", re.IGNORECASE),           # SGX untrusted AE
    re.compile(r"OCALL", re.IGNORECASE),
    re.compile(r"launch_enclave", re.IGNORECASE),
    re.compile(r"destroy_enclave", re.IGNORECASE),
    re.compile(r"ecall_", re.IGNORECASE),              # Host calling into enclave
    re.compile(r"init_enclave", re.IGNORECASE),
    re.compile(r"create_enclave", re.IGNORECASE),
    # Gramine host patterns — code calling INTO the enclave from outside
    re.compile(r"pruntime_client", re.IGNORECASE),
    re.compile(r"pruntime_endpoint", re.IGNORECASE),
    re.compile(r"new_pruntime_client", re.IGNORECASE),
]


def classify_file_zone(file_path: Path, repo_path: Path) -> tuple[TrustZone, str]:
    """Classify a single file's trust zone based on path and content.

    Uses three signals (in priority order):
    1. File path patterns (enclave/, host/, trusted/, etc.)
    2. TEE API usage in file content
    3. Keyword density heuristics

    Returns (zone, source) where source is "heuristic" for the current
    classification method. Manifest and LLM sources are overlaid later.
    """
    rel_path = str(file_path.relative_to(repo_path))
    path_lower = rel_path.lower().replace("\\", "/")

    # Signal 1: Strong path-based classification
    for pattern in _TRUSTED_PATH_PATTERNS:
        if pattern.search(path_lower):
            return TrustZone.TRUSTED, "heuristic"

    for pattern in _UNTRUSTED_PATH_PATTERNS:
        if pattern.search(path_lower):
            return TrustZone.UNTRUSTED, "heuristic"

    # Signal 2: Content-based classification
    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        return TrustZone.UNKNOWN, "heuristic"

    trusted_hits = sum(1 for p in _TRUSTED_CONTENT_PATTERNS if p.search(content))
    untrusted_hits = sum(1 for p in _UNTRUSTED_CONTENT_PATTERNS if p.search(content))

    if trusted_hits >= 2 and untrusted_hits == 0:
        return TrustZone.TRUSTED, "heuristic"
    if untrusted_hits >= 2 and trusted_hits == 0:
        return TrustZone.UNTRUSTED, "heuristic"
    if trusted_hits >= 1 and untrusted_hits >= 1:
        return TrustZone.MIXED, "heuristic"

    # Signal 3: TEE boundary keyword density — only for compiled languages
    # JS/TS frontend files mentioning TEE concepts are NOT trusted code
    tee_capable_extensions = {".rs", ".c", ".cc", ".cpp", ".h", ".go"}
    if file_path.suffix in tee_capable_extensions:
        content_lower = content.lower()
        boundary_hits = sum(1 for kw in _TEE_BOUNDARY_KEYWORDS if kw in content_lower)
        if boundary_hits >= 4:
            return TrustZone.MIXED, "heuristic"
        if boundary_hits >= 2:
            return TrustZone.TRUSTED, "heuristic"

    return TrustZone.UNKNOWN, "heuristic"


def _detect_gramine_enclave_root(repo_path: Path) -> str | None:
    """Find the Gramine enclave crate root (directory with Cargo.toml near pal_gramine)."""
    for marker in ["pal_gramine.rs", "pal_gramine.c"]:
        for f in repo_path.rglob(marker):
            # Walk up to find the crate root (directory containing Cargo.toml)
            candidate = f.parent
            while candidate != repo_path and candidate != candidate.parent:
                if (candidate / "Cargo.toml").exists():
                    return str(candidate.relative_to(repo_path))
                candidate = candidate.parent
            return str(f.parent.relative_to(repo_path))
    for f in repo_path.rglob("*.manifest.template"):
        parent = f.parent
        siblings = {s.name for s in parent.iterdir() if s.is_file()}
        if any("gramine" in s for s in siblings):
            return str(parent.relative_to(repo_path))
    return None


def _parse_cargo_local_deps(cargo_toml_path: Path, repo_path: Path) -> list[str]:
    """Extract local path dependencies from a Cargo.toml file.

    Returns list of relative directory paths within the repo.
    """
    if not cargo_toml_path.exists():
        return []
    try:
        content = cargo_toml_path.read_text(errors="ignore")
    except OSError:
        return []
    # Match: name = { path = "../../crates/foo" } or path = "../bar"
    paths = re.findall(r'path\s*=\s*"([^"]+)"', content)
    result = []
    for p in paths:
        resolved = (cargo_toml_path.parent / p).resolve()
        try:
            rel = str(resolved.relative_to(repo_path.resolve()))
            result.append(rel)
        except ValueError:
            pass  # Outside repo
    return result


def _build_gramine_trusted_dirs(repo_path: Path) -> set[str]:
    """Detect Gramine enclave and its local crate dependencies as trusted dirs."""
    enclave_root = _detect_gramine_enclave_root(repo_path)
    if not enclave_root:
        return set()
    trusted = {enclave_root}
    # Parse enclave's Cargo.toml for local deps
    cargo_toml = repo_path / enclave_root / "Cargo.toml"
    for dep_dir in _parse_cargo_local_deps(cargo_toml, repo_path):
        trusted.add(dep_dir)
    return trusted


def build_zone_map(repo_path: Path) -> ZoneMap:
    """Build a zone classification map for all source files in the repo.

    Scans for source files, EDL files, and classifies each into trust zones.
    """
    zones: dict[str, TrustZone] = {}
    zone_source: dict[str, str] = {}
    edl_files: list[str] = []
    entry_points: dict[str, list[str]] = {}

    for ext in _SOURCE_EXTENSIONS:
        for file_path in repo_path.rglob(f"*{ext}"):
            parts = file_path.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            str_path = str(file_path)
            if "registry/src" in str_path or ".cargo" in str_path:
                continue
            rel = str(file_path.relative_to(repo_path))
            zone, source = classify_file_zone(file_path, repo_path)
            if zone != TrustZone.UNKNOWN:
                zones[rel] = zone
                zone_source[rel] = source

    # Gramine-aware reclassification: detect enclave root + deps → TRUSTED
    gramine_trusted = _build_gramine_trusted_dirs(repo_path)
    if gramine_trusted:
        for rel_path in list(zones.keys()):
            # Check if file is under any trusted Gramine directory
            for trusted_dir in gramine_trusted:
                if rel_path.startswith(trusted_dir + "/") or rel_path.startswith(trusted_dir + "\\"):
                    zones[rel_path] = TrustZone.TRUSTED
                    zone_source[rel_path] = "gramine_enclave"
                    break
        # Host-side reclassification: standalone dirs NOT under enclave are untrusted
        enclave_root = _detect_gramine_enclave_root(repo_path)
        if enclave_root:
            for rel_path in list(zones.keys()):
                # Files in standalone/ that aren't under enclave root → UNTRUSTED
                # This overrides even heuristic TRUSTED — the enclave boundary is clear
                parts = rel_path.split("/")
                if len(parts) >= 1 and parts[0] == "standalone" and not rel_path.startswith(enclave_root):
                    zones[rel_path] = TrustZone.UNTRUSTED
                    zone_source[rel_path] = "gramine_host"
        logger.info(
            "Gramine zone overlay: %d trusted dirs (enclave root: %s)",
            len(gramine_trusted), enclave_root,
        )

    # Discover EDL files (define ECALL/OCALL interfaces)
    for edl in repo_path.rglob("*.edl"):
        rel = str(edl.relative_to(repo_path))
        edl_files.append(rel)
        try:
            content = edl.read_text(errors="ignore")
            ecalls = re.findall(r"trusted\s+\{[^}]*\}", content, re.DOTALL)
            ocalls = re.findall(r"untrusted\s+\{[^}]*\}", content, re.DOTALL)
            funcs = re.findall(r"(?:void|uint\w*|int\w*|size_t|char|bool)\s+(\w+)\s*\(", content)
            if funcs:
                entry_points[rel] = funcs
        except OSError:
            pass

    logger.info(
        "Zone map: %d files classified (%d trusted, %d untrusted, %d mixed, %d EDL files)",
        len(zones),
        sum(1 for z in zones.values() if z == TrustZone.TRUSTED),
        sum(1 for z in zones.values() if z == TrustZone.UNTRUSTED),
        sum(1 for z in zones.values() if z == TrustZone.MIXED),
        len(edl_files),
    )

    return ZoneMap(zones=zones, edl_files=edl_files, entry_points=entry_points, zone_source=zone_source)


def overlay_manifest_zones(
    zone_map: ZoneMap,
    manifest_trusted_files: list[str],
) -> ZoneMap:
    """Overlay manifest-derived zones onto an existing heuristic ZoneMap.

    Manifest zones override heuristic zones where the manifest provides
    explicit trusted file paths. Files NOT covered by the manifest keep
    their heuristic classification.
    """
    if not manifest_trusted_files:
        return zone_map

    zones = dict(zone_map.zones)
    zone_source = dict(zone_map.zone_source)

    for trusted_pattern in manifest_trusted_files:
        # Match manifest paths against zone_map entries
        normalized_pattern = trusted_pattern.replace("\\", "/")
        # Handle glob-like patterns from manifest (e.g., "*")
        if normalized_pattern in ("*", ".*", ""):
            continue

        for rel_path in list(zones.keys()):
            normalized_path = rel_path.replace("\\", "/")
            if (
                normalized_path.endswith(normalized_pattern)
                or normalized_pattern.endswith(normalized_path)
                or normalized_path.startswith(normalized_pattern.rstrip("*"))
            ):
                zones[rel_path] = TrustZone.TRUSTED
                zone_source[rel_path] = "manifest"

    return zone_map.model_copy(update={"zones": zones, "zone_source": zone_source})


# ---------------------------------------------------------------------------
# LLM-assisted Project Role Inference
# ---------------------------------------------------------------------------

class DirectoryZone(BaseModel):
    """A directory classified as trusted or untrusted."""

    directory: str  # e.g. "runtime", "client-sdk"
    zone: str  # "trusted" | "untrusted"


class ProjectTEERole(BaseModel):
    """LLM response for project-level TEE role classification."""

    role: str  # "enclave_only" | "host_only" | "mixed"
    reasoning: str
    confidence: float  # 0.0 - 1.0
    directory_zones: list[DirectoryZone] = []


def _gather_project_context(repo_path: Path, max_lines: int = 150) -> str:
    """Collect README, directory structure, and key config files for LLM context."""
    parts: list[str] = []

    # Top-level directory listing (2 levels deep)
    lines: list[str] = ["Directory structure:"]
    for item in sorted(repo_path.iterdir()):
        if item.name.startswith(".") or item.name in _SKIP_DIRS:
            continue
        if item.is_dir():
            subdirs = sorted(
                s.name for s in item.iterdir()
                if s.is_dir() and not s.name.startswith(".") and s.name not in _SKIP_DIRS
            )[:8]
            if subdirs:
                lines.append(f"  {item.name}/ → {', '.join(subdirs)}")
            else:
                lines.append(f"  {item.name}/")
        else:
            lines.append(f"  {item.name}")
    parts.append("\n".join(lines[:60]))

    # README (first max_lines lines)
    for name in ("README.md", "README.rst", "README.txt", "README"):
        readme = repo_path / name
        if readme.exists():
            try:
                content = readme.read_text(errors="ignore")
                preview = "\n".join(content.splitlines()[:max_lines])
                parts.append(f"README ({name}):\n{preview}")
            except OSError:
                pass
            break

    # Cargo.toml (shows crate dependencies and name)
    cargo = repo_path / "Cargo.toml"
    if cargo.exists():
        try:
            parts.append(f"Cargo.toml:\n{cargo.read_text(errors='ignore')[:2000]}")
        except OSError:
            pass

    # package.json for Node projects
    pkg = repo_path / "package.json"
    if pkg.exists():
        try:
            parts.append(f"package.json:\n{pkg.read_text(errors='ignore')[:1500]}")
        except OSError:
            pass

    # go.mod for Go projects
    gomod = repo_path / "go.mod"
    if gomod.exists():
        try:
            parts.append(f"go.mod:\n{gomod.read_text(errors='ignore')[:1000]}")
        except OSError:
            pass

    return "\n\n".join(parts)


def infer_project_tee_role(
    repo_path: Path,
    zone_map: ZoneMap,
    client,  # LLMClient — typed as Any to avoid circular import
) -> ProjectTEERole | None:
    """Use LLM to classify the entire project's TEE role.

    Determines if the repo is enclave-only, host-only, or mixed.
    Only called when heuristic classification produces many MIXED/UNKNOWN zones.
    """
    from pydantic import ValidationError

    # Count zone distribution
    total = len(zone_map.zones)
    if total == 0:
        return None
    mixed_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.MIXED)
    unknown_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.UNKNOWN)
    trusted_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.TRUSTED)
    untrusted_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.UNTRUSTED)

    # Skip inference if zones are already well-classified
    well_classified = trusted_count + untrusted_count
    ambiguous = mixed_count + unknown_count
    sparse = total < 10
    high_ambiguity = ambiguous > total * 0.1
    if not sparse and not high_ambiguity:
        logger.info(
            "Project role inference: skipped (zones already well-classified: "
            "%d clear vs %d ambiguous, total=%d)", well_classified, ambiguous, total,
        )
        return None

    context = _gather_project_context(repo_path)
    if len(context) < 50:
        logger.info("Project role inference: insufficient context (%d chars)", len(context))
        return None

    # Truncate to keep LLM call fast
    if len(context) > 6000:
        context = context[:6000] + "\n...[truncated]"

    system_prompt = (
        "You are a TEE security analyst. Classify this code repository's role in a TEE architecture.\n"
        "Respond with ONLY valid JSON matching this schema:\n"
        '{"role": "<enclave_only|host_only|mixed>", '
        '"reasoning": "<brief explanation>", '
        '"confidence": <0.0-1.0>, '
        '"directory_zones": [{"directory": "<path>", "zone": "<trusted|untrusted>"}]}\n\n'
        "Definitions:\n"
        "- enclave_only: Code that runs INSIDE a TEE/enclave (e.g., confidential computing runtime, "
        "SGX enclave implementation, TDX guest code). It IS the protected component.\n"
        "- host_only: Code that runs OUTSIDE a TEE on the untrusted host. It may launch/manage/verify "
        "enclaves but does NOT execute inside one (e.g., DCAP quote verification library, enclave launcher, "
        "attestation verifier, client SDK).\n"
        "- mixed: Repository contains BOTH enclave and host code with a clear trust boundary between them "
        "(e.g., an app with separate enclave/ and host/ directories, or EDL-defined ECALL/OCALL boundary).\n\n"
        "For directory_zones: classify the TOP-LEVEL directories (and key subdirectories) as trusted or untrusted.\n"
        "This is ESSENTIAL for mixed projects. For enclave_only/host_only, list is optional.\n\n"
        "Key signals:\n"
        "- If the project IS a TEE runtime/confidential VM → enclave_only\n"
        "- If the project VERIFIES/quotes/launches enclaves but doesn't run inside one → host_only\n"
        "- If the project has both sides with explicit boundary → mixed\n"
        "- SDK/framework libraries that SUPPORT TEE development → typically host_only (they help build "
        "enclave apps but themselves run on the host)\n"
        "- A blockchain node that optionally uses TEE → mixed (has both TEE and non-TEE paths)"
    )

    zone_summary = (
        f"Current heuristic zone map: {total} files "
        f"({trusted_count} trusted, {untrusted_count} untrusted, "
        f"{mixed_count} mixed, {unknown_count} unknown)"
    )

    try:
        role = client.complete_structured(
            system=system_prompt,
            user=f"{context}\n\n{zone_summary}",
            schema=ProjectTEERole,
            temperature=0.0,
        )
        if role.role not in ("enclave_only", "host_only", "mixed"):
            logger.warning("Project role inference: unexpected role '%s', ignoring", role.role)
            return None
        logger.info(
            "Project role inference: %s (confidence=%.2f) — %s",
            role.role, role.confidence, role.reasoning[:200],
        )
        return role
    except Exception as e:
        logger.warning("Project role inference failed: %s", str(e)[:200])
        return None


def apply_project_role_to_zones(
    zone_map: ZoneMap,
    role: ProjectTEERole,
    repo_path: Path | None = None,
) -> ZoneMap:
    """Override zone classifications based on inferred project TEE role.

    For enclave_only/host_only: overrides all heuristic MIXED/UNKNOWN zones.
    For mixed with directory_zones: classifies files by their directory.
    Only overrides heuristic-sourced zones — preserves manifest and gramine.
    When repo_path is provided and the zone map is sparse, also adds unclassified
    source files.
    """
    if role.confidence < 0.6:
        return zone_map

    zones = dict(zone_map.zones)
    zone_source = dict(zone_map.zone_source)
    llm_reasoning = dict(zone_map.llm_reasoning)
    source_label = "llm_inferred"

    overridden = 0
    added = 0

    if role.role == "mixed" and role.directory_zones:
        # Mixed project with directory-level classification
        dir_zone_map: dict[str, TrustZone] = {}
        repo_name = repo_path.name if repo_path else ""
        for dz in role.directory_zones:
            zone_val = TrustZone.TRUSTED if dz.zone == "trusted" else TrustZone.UNTRUSTED
            # Normalize: strip any path prefix before the repo root
            dir_path = dz.directory.replace("\\", "/").strip("/")
            if repo_name and "/" in dir_path:
                parts = dir_path.split("/")
                for i, part in enumerate(parts):
                    if part == repo_name and i + 1 < len(parts):
                        dir_path = "/".join(parts[i + 1:])
                        break
            if dir_path:
                dir_zone_map[dir_path] = zone_val

        reasoning = f"Project classified as mixed: {role.reasoning}"

        # Override existing MIXED files using directory zones
        for rel_path in list(zones.keys()):
            current_source = zone_source.get(rel_path, "heuristic")
            if current_source not in ("heuristic",):
                continue
            if zones[rel_path] not in (TrustZone.MIXED, TrustZone.UNKNOWN):
                continue
            for dir_prefix, dir_zone in dir_zone_map.items():
                if rel_path.startswith(dir_prefix + "/") or rel_path.startswith(dir_prefix + "\\"):
                    zones[rel_path] = dir_zone
                    zone_source[rel_path] = source_label
                    llm_reasoning[rel_path] = reasoning
                    overridden += 1
                    break

        # Add unclassified source files using directory zones
        if repo_path and role.confidence >= 0.7 and dir_zone_map:
            for ext in _SOURCE_EXTENSIONS:
                for file_path in repo_path.rglob(f"*{ext}"):
                    parts = file_path.relative_to(repo_path).parts
                    if any(p in _SKIP_DIRS for p in parts):
                        continue
                    str_path = str(file_path)
                    if "registry/src" in str_path or ".cargo" in str_path:
                        continue
                    rel = str(file_path.relative_to(repo_path))
                    if rel in zones:
                        continue
                    for dir_prefix, dir_zone in dir_zone_map.items():
                        if rel.startswith(dir_prefix + "/") or rel.startswith(dir_prefix + "\\"):
                            zones[rel] = dir_zone
                            zone_source[rel] = source_label
                            llm_reasoning[rel] = reasoning
                            added += 1
                            break

    elif role.role in ("enclave_only", "host_only"):
        target_zone = TrustZone.TRUSTED if role.role == "enclave_only" else TrustZone.UNTRUSTED
        reasoning = f"Project classified as {role.role}: {role.reasoning}"

        for rel_path in list(zones.keys()):
            current_source = zone_source.get(rel_path, "heuristic")
            if current_source not in ("heuristic",):
                continue
            current_zone = zones[rel_path]
            if current_zone in (TrustZone.MIXED, TrustZone.UNKNOWN):
                zones[rel_path] = target_zone
                zone_source[rel_path] = source_label
                llm_reasoning[rel_path] = reasoning
                overridden += 1
            elif current_zone != target_zone and role.confidence >= 0.8:
                zones[rel_path] = target_zone
                zone_source[rel_path] = source_label
                llm_reasoning[rel_path] = reasoning
                overridden += 1

        # Add unclassified source files when zone map is sparse
        if repo_path and role.confidence >= 0.7 and len(zones) < 20:
            for ext in _SOURCE_EXTENSIONS:
                for file_path in repo_path.rglob(f"*{ext}"):
                    parts = file_path.relative_to(repo_path).parts
                    if any(p in _SKIP_DIRS for p in parts):
                        continue
                    str_path = str(file_path)
                    if "registry/src" in str_path or ".cargo" in str_path:
                        continue
                    rel = str(file_path.relative_to(repo_path))
                    if rel not in zones:
                        zones[rel] = target_zone
                        zone_source[rel] = source_label
                        llm_reasoning[rel] = reasoning
                        added += 1
    else:
        # Mixed without directory_zones or unknown role — no override
        return zone_map

    logger.info(
        "Applied project role '%s': overrode %d zones, added %d new, total %d zones",
        role.role, overridden, added, len(zones),
    )

    return zone_map.model_copy(update={
        "zones": zones,
        "zone_source": zone_source,
        "llm_reasoning": llm_reasoning,
        "project_role": role.role,
        "project_role_reasoning": role.reasoning,
    })


def reconcile_directory_zones(zone_map: ZoneMap) -> ZoneMap:
    """Enforce directory-level consistency in zone classifications.

    After heuristic/gramine/LLM layers produce per-file zones, this pass
    ensures files in the same directory share a consistent zone.  Directories
    with conflicting classifications are resolved by:

    1. If any file has gramine or manifest source → use that zone (highest confidence).
    2. If sources disagree (heuristic vs llm_inferred), prefer llm_inferred —
       the LLM reasons about the component's role, not just keyword density.
    3. Otherwise, majority vote among all classified files (>50%).
    """
    zones = dict(zone_map.zones)
    zone_source = dict(zone_map.zone_source)
    llm_reasoning = dict(zone_map.llm_reasoning)

    # Group files by parent directory
    dir_files: dict[str, list[str]] = {}
    for rel_path in zones:
        parent = str(Path(rel_path).parent)
        dir_files.setdefault(parent, []).append(rel_path)

    changed = 0
    for dir_path, files in dir_files.items():
        if len(files) < 2:
            continue

        # Collect (zone, source) pairs
        dir_entries = [(zones[f], zone_source.get(f, "heuristic")) for f in files]
        unique_zones = set(z for z, _ in dir_entries)
        if len(unique_zones) <= 1:
            continue

        # Priority 1: gramine/manifest source determines the directory's zone
        high_priority_zone = None
        for z, s in dir_entries:
            if s in ("gramine_enclave", "gramine_host", "manifest"):
                high_priority_zone = z
                break

        if high_priority_zone is not None:
            consensus = high_priority_zone
        else:
            # Priority 2: if llm_inferred and heuristic disagree, prefer llm_inferred
            llm_zones = {z for z, s in dir_entries if s == "llm_inferred"}
            heuristic_zones = {z for z, s in dir_entries if s == "heuristic"}
            if llm_zones and heuristic_zones and llm_zones != heuristic_zones:
                # LLM has directory-level context about the component's role
                llm_counts: dict[TrustZone, int] = {}
                for z, s in dir_entries:
                    if s == "llm_inferred":
                        llm_counts[z] = llm_counts.get(z, 0) + 1
                consensus = max(llm_counts, key=llm_counts.get)
            else:
                # Priority 3: majority vote (>50%)
                zone_counts: dict[TrustZone, int] = {}
                for z, _ in dir_entries:
                    zone_counts[z] = zone_counts.get(z, 0) + 1
                total = len(files)
                best_zone = max(zone_counts, key=zone_counts.get)
                if zone_counts[best_zone] / total > 0.5:
                    consensus = best_zone
                else:
                    continue  # No clear majority, leave as-is

        # Apply consensus to all files in directory
        for f in files:
            if zones[f] != consensus:
                zones[f] = consensus
                zone_source[f] = "reconciled"
                changed += 1

    if changed:
        logger.info(
            "Directory reconciliation: %d files reclassified for consistency", changed,
        )

    return zone_map.model_copy(update={
        "zones": zones,
        "zone_source": zone_source,
        "llm_reasoning": llm_reasoning,
    })


def classify_code_location(
    file_path: str, zone_map: ZoneMap, repo_path: Path | None = None,
) -> TrustZone:
    """Classify the trust zone of a specific code location.

    Looks up the file in the zone map, falling back to UNKNOWN.
    """
    normalized = file_path.replace("\\", "/")
    for rel_path, zone in zone_map.zones.items():
        if normalized.endswith(rel_path) or rel_path.endswith(normalized):
            return zone
    return TrustZone.UNKNOWN


def lookup_zone_source(file_path: str, zone_map: ZoneMap) -> str:
    """Look up the zone classification source for a file.

    Returns "heuristic", "manifest", "llm_inferred", or "unknown".
    """
    normalized = file_path.replace("\\", "/")
    for rel_path, source in zone_map.zone_source.items():
        if normalized.endswith(rel_path) or rel_path.endswith(normalized):
            return source
    return "unknown"


_SKIP_DIRS = frozenset({
    "target", "build", "dist", "node_modules", ".git", "cargo-home",
    "codeql-dbs", "tee-audit-output", "cargo-target", "vendor",
    "__pycache__", ".venv",
})

_SOURCE_EXTENSIONS = {".rs", ".go", ".py", ".ts", ".js", ".c", ".cc", ".cpp", ".h", ".hpp", ".sol"}

# Patterns for cross-file references across common languages
_IMPORT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".rs": [
        re.compile(r"use\s+([\w:]+)"),
        re.compile(r"mod\s+(\w+)"),
        re.compile(r"extern\s+crate\s+(\w+)"),
        re.compile(r"(?:unsafe\s+)?fn\s+(\w+)"),
        re.compile(r"(\w+)::(\w+)"),
    ],
    ".go": [
        re.compile(r'"([^"]+)"'),
        re.compile(r"(\w+)\.(?:Call|Invoke|Do|Handle|Process|Execute)"),
    ],
    ".py": [
        re.compile(r"from\s+([\w.]+)\s+import"),
        re.compile(r"import\s+([\w.]+)"),
        re.compile(r"(\w+)\.(?:call|invoke|handle|process|execute)"),
    ],
    ".ts": [
        re.compile(r"from\s+['\"]([^'\"]+)['\"]"),
        re.compile(r"import\s+.*from\s+['\"]([^'\"]+)['\"]"),
        re.compile(r"(\w+)\.(?:call|invoke|handle|process|execute)"),
    ],
}

_TEE_BOUNDARY_KEYWORDS = {
    "ecall", "ocall", "enclave", "trusted", "untrusted",
    "attestation", "quote", "seal", "unseal", "measurement",
    "mrenclave", "mrsigner", "report", "verify_report",
    "dcap", "quote_verification", "key_policy",
    "sgx", "tdx", "sev", "nitro", "cc", "tee",
}


def discover_related_files(
    repo_path: Path,
    seed_files: list[str],
    max_depth: int = 2,
    max_files: int = 8,
) -> list[Path]:
    """Walk code references from seed files to discover related files.

    Args:
        repo_path: Root of the cloned repository.
        seed_files: Initial file paths (relative to repo_root) to start from.
        max_depth: How many hops to follow (default 2).
        max_files: Maximum number of related files to return.

    Returns:
        Deduplicated list of discovered file paths (absolute).
    """
    visited: set[str] = set()
    discovered: list[Path] = []
    frontier: list[str] = list(seed_files)

    for _ in range(max_depth):
        if not frontier or len(discovered) >= max_files:
            break

        next_frontier: list[str] = []
        for rel_path in frontier:
            if rel_path in visited:
                continue
            visited.add(rel_path)

            abs_path = repo_path / rel_path
            if not abs_path.exists() or not abs_path.is_file():
                continue

            if abs_path.suffix not in _SOURCE_EXTENSIONS:
                continue

            discovered.append(abs_path)
            if len(discovered) >= max_files:
                break

            refs = _extract_references(abs_path)
            for ref in refs:
                resolved = _resolve_reference(repo_path, ref, abs_path)
                for r in resolved:
                    rel = str(r.relative_to(repo_path))
                    if rel not in visited and rel not in next_frontier:
                        next_frontier.append(rel)

        frontier = next_frontier

    return discovered[:max_files]


def _is_valid_reference(ref: str) -> bool:
    """Check if an extracted string looks like a real code reference, not code content."""
    if len(ref) > 120 or len(ref) < 2:
        return False
    # Reject references containing code-like characters or whitespace
    if any(c in ref for c in "\n\r\t(){}[];=<>!,+-*/%&|^~"):
        return False
    # Must contain at least one alphanumeric character
    if not any(c.isalnum() for c in ref):
        return False
    return True


def _extract_references(file_path: Path) -> list[str]:
    """Extract cross-file reference strings from a source file."""
    refs: list[str] = []
    suffix = file_path.suffix
    patterns = _IMPORT_PATTERNS.get(suffix, [])

    try:
        text = file_path.read_text(errors="ignore")
    except OSError:
        return refs

    seen: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            ref = match.group(1)
            if ref not in seen and _is_valid_reference(ref):
                seen.add(ref)
                refs.append(ref)

    return refs


def _resolve_reference(repo_path: Path, ref: str, source_file: Path) -> list[Path]:
    """Try to resolve a reference string to actual file paths."""
    candidates: list[Path] = []

    # Direct file match
    direct = repo_path / ref
    if direct.exists() and direct.is_file():
        candidates.append(direct)
        return candidates

    # Try as relative path with source extensions
    for ext in _SOURCE_EXTENSIONS:
        with_ext = repo_path / f"{ref}{ext}"
        if with_ext.exists():
            candidates.append(with_ext)
            return candidates

    # Rust crate::module::item → module/item.rs or module/mod.rs
    if "::" in ref:
        parts = ref.split("::")
        # Try module/item.rs
        module_path = repo_path / "/".join(parts[:-1]) / f"{parts[-1]}.rs"
        if module_path.exists():
            candidates.append(module_path)
        # Try module/mod.rs
        mod_path = repo_path / "/".join(parts) / "mod.rs"
        if mod_path.exists():
            candidates.append(mod_path)
        # Try flat: parts[-1].rs
        flat = repo_path / "src" / f"{parts[-1]}.rs"
        if flat.exists() and flat not in candidates:
            candidates.append(flat)

    # Filename search (last resort, limited)
    base_name = ref.split(".")[-1].split("::")[-1].split("/")[-1]
    if len(base_name) > 2:
        for ext in (".rs", ".go", ".py", ".ts"):
            for match in repo_path.rglob(f"{base_name}{ext}"):
                if match.is_file() and match not in candidates:
                    candidates.append(match)
                    if len(candidates) >= 2:
                        return candidates

    return candidates


def discover_tee_boundary_files(repo_path: Path) -> list[Path]:
    """Find files likely involved in TEE trust boundary crossings.

    Scans for TEE-related keywords in file content to identify boundary files.
    """
    candidates: list[Path] = []
    seen: set[str] = set()

    for ext in _SOURCE_EXTENSIONS:
        for file_path in repo_path.rglob(f"*{ext}"):
            if _is_test_or_vendor(file_path):
                continue
            try:
                text = file_path.read_text(errors="ignore").lower()
            except OSError:
                continue

            keyword_hits = sum(1 for kw in _TEE_BOUNDARY_KEYWORDS if kw in text)
            if keyword_hits >= 2:
                rel = str(file_path.relative_to(repo_path))
                if rel not in seen:
                    seen.add(rel)
                    candidates.append(file_path)

    return candidates


def build_fingerprint_map(
    fingerprint_data: dict | None = None,
    zone_map: ZoneMap | None = None,
) -> str:
    """Format fingerprint data + zone map as a trust boundary map for the LLM prompt."""
    if not fingerprint_data and not zone_map:
        return ""

    parts: list[str] = []

    tee_platforms = fingerprint_data.get("tee_platforms", {}) if fingerprint_data else {}
    if tee_platforms:
        platforms = ", ".join(tee_platforms.keys())
        parts.append(f"TEE Platforms: {platforms}")
        for platform, lines in tee_platforms.items():
            if lines:
                parts.append(f"  {platform} indicators: {', '.join(str(l) for l in lines[:5])}")

    trust_artifacts = fingerprint_data.get("trust_artifacts", {}) if fingerprint_data else {}
    if trust_artifacts:
        parts.append("Trust Artifacts:")
        for artifact_type, lines in trust_artifacts.items():
            if lines:
                parts.append(f"  {artifact_type}: {', '.join(str(l) for l in lines[:5])}")

    critical_paths = fingerprint_data.get("critical_paths", []) if fingerprint_data else []
    if critical_paths:
        parts.append(f"Critical Paths: {', '.join(str(p) for p in critical_paths[:10])}")

    # Zone classification summary
    if zone_map and zone_map.zones:
        trusted = [p for p, z in zone_map.zones.items() if z == TrustZone.TRUSTED]
        untrusted = [p for p, z in zone_map.zones.items() if z == TrustZone.UNTRUSTED]
        mixed = [p for p, z in zone_map.zones.items() if z == TrustZone.MIXED]
        parts.append(f"\nTrust Zone Classification ({len(zone_map.zones)} files):")
        if trusted:
            parts.append(f"  Trusted (enclave): {', '.join(trusted[:15])}")
        if untrusted:
            parts.append(f"  Untrusted (host): {', '.join(untrusted[:15])}")
        if mixed:
            parts.append(f"  Mixed (boundary): {', '.join(mixed[:10])}")
        if zone_map.edl_files:
            parts.append(f"  EDL interfaces: {', '.join(zone_map.edl_files)}")

    return "\n".join(parts) if parts else ""


def trace_call_chain(
    repo_path: Path,
    seed_files: list[str],
    zone_map: ZoneMap,
    max_depth: int = 4,
    max_files: int = 15,
) -> CallChain:
    """Trace a call chain from seed files with zone annotations.

    Enhanced version of discover_related_files that produces structured
    CallChain output with zone annotations and boundary crossing detection.
    """
    hops: list[CallChainHop] = []
    visited: set[str] = set()
    frontier: list[tuple[str, int]] = [(f, 0) for f in seed_files]
    zones_crossed = 0

    for _ in range(max_depth):
        if not frontier or len(hops) >= max_files:
            break

        next_frontier: list[tuple[str, int]] = []
        for rel_path, depth in frontier:
            if rel_path in visited or len(hops) >= max_files:
                continue
            visited.add(rel_path)

            abs_path = repo_path / rel_path
            if not abs_path.exists() or not abs_path.is_file():
                continue
            if abs_path.suffix not in _SOURCE_EXTENSIONS:
                continue

            zone = classify_code_location(rel_path, zone_map)

            # Detect function names from the file
            func_names = _extract_function_names(abs_path)

            crosses = False
            if hops and hops[-1].zone != TrustZone.UNKNOWN and zone != TrustZone.UNKNOWN:
                crosses = hops[-1].zone != zone
                if crosses:
                    zones_crossed += 1

            hops.append(CallChainHop(
                file=rel_path,
                function=func_names[0] if func_names else "",
                zone=zone,
                crosses_boundary=crosses,
            ))

            # Follow references deeper
            if depth < max_depth - 1:
                refs = _extract_references(abs_path)
                for ref in refs:
                    resolved = _resolve_reference(repo_path, ref, abs_path)
                    for r in resolved:
                        r_rel = str(r.relative_to(repo_path))
                        if r_rel not in visited:
                            next_frontier.append((r_rel, depth + 1))

        frontier = next_frontier

    # An end-to-end chain has evidence spanning from source to sink
    has_evidence = (
        len(hops) >= 2
        and any(h.zone == TrustZone.TRUSTED for h in hops)
        and any(h.zone in (TrustZone.UNTRUSTED, TrustZone.MIXED) for h in hops)
    )

    return CallChain(
        hops=hops,
        zones_crossed=zones_crossed,
        depth=max((i + 1) for i in range(len(hops))) if hops else 0,
        has_end_to_end_evidence=has_evidence,
    )


def format_call_chain_for_prompt(chain: CallChain) -> str:
    """Format a CallChain as human-readable text for LLM prompts."""
    if not chain.hops:
        return "[No call chain traced]"

    lines: list[str] = []
    lines.append(f"Invocation chain (depth {chain.depth}, {chain.zones_crossed} trust boundary crossings):")

    for i, hop in enumerate(chain.hops):
        zone_label = hop.zone.value.upper()
        boundary_marker = " <<TRUST BOUNDARY>>" if hop.crosses_boundary else ""
        func = f"::{hop.function}" if hop.function else ""
        lines.append(f"  {i + 1}. [{zone_label}] {hop.file}{func}{boundary_marker}")

    if chain.has_end_to_end_evidence:
        lines.append("  [Chain spans trusted and untrusted zones — end-to-end evidence available]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Function name extraction (for call chain tracing)
# ---------------------------------------------------------------------------

_FUNCTION_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".rs": [
        re.compile(r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)"),
        re.compile(r"(?:pub\s+)?(?:const|static)\s+(\w+)\s*[:=]"),
    ],
    ".go": [
        re.compile(r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)"),
    ],
    ".py": [
        re.compile(r"def\s+(\w+)"),
        re.compile(r"class\s+(\w+)"),
    ],
    ".ts": [
        re.compile(r"(?:export\s+)?(?:async\s+)?function\s+(\w+)"),
        re.compile(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\("),
    ],
    ".c": [
        re.compile(r"(?:static\s+)?(?:inline\s+)?\w+\s+(\w+)\s*\("),
    ],
}


def _extract_function_names(file_path: Path, max_names: int = 10) -> list[str]:
    """Extract top-level function names from a source file."""
    suffix = file_path.suffix
    patterns = _FUNCTION_PATTERNS.get(suffix, [])
    if not patterns:
        return []

    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        return []

    names: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(content):
            name = match.group(1)
            if name not in seen and not name.startswith("_"):
                seen.add(name)
                names.append(name)
                if len(names) >= max_names:
                    return names
    return names


def _is_test_or_vendor(file_path: Path) -> bool:
    """Check if file is in test, vendor, or build directory."""
    parts = file_path.parts
    skip_dirs = {"test", "tests", "testing", "examples", "benches", "vendor", "target", "node_modules"}
    return any(p.lower() in skip_dirs for p in parts)


# ---------------------------------------------------------------------------
# Invocation Chain Tracing (A2-A6)
# ---------------------------------------------------------------------------

# Language keywords to filter out from call site extraction
_CALL_KEYWORDS = frozenset({
    "if", "else", "while", "for", "match", "return", "break", "continue",
    "Some", "None", "Ok", "Err", "true", "false", "let", "mut", "const",
    "pub", "fn", "impl", "struct", "enum", "trait", "type", "where",
    "async", "await", "unsafe", "extern", "use", "mod", "self", "super",
    "as", "in", "ref", "move", "dyn", "static", "loop",
    # Go
    "func", "go", "defer", "select", "switch", "case", "default", "chan",
    "range", "var", "package", "import",
    # Python
    "def", "class", "with", "try", "except", "finally", "yield", "lambda",
    "and", "or", "not", "is", "del", "global", "nonlocal", "assert", "pass",
    "raise", "from",
})

# Common stdlib/utility calls that pollute the caller graph — filter these out
# to keep BFS backward search focused on security-relevant paths.
_NOISE_CALLEE_NAMES = frozenset({
    # Rust stdlib utilities
    "clone", "to_owned", "to_string", "into", "from", "as_ref", "as_mut",
    "borrow", "deref", "drop", "default", "new", "with_capacity",
    "len", "is_empty", "push", "pop", "get", "get_mut", "insert", "remove",
    "contains_key", "iter", "into_iter", "collect", "map", "filter", "for_each",
    "unwrap", "unwrap_or", "unwrap_or_else", "unwrap_or_default", "unwrap_none",
    "expect", "ok", "err", "is_ok", "is_err", "is_some", "is_none",
    "to_vec", "to_slice", "as_slice", "as_str", "to_bytes", "from_slice",
    "format", "println", "print", "eprintln", "eprint", "write", "writeln",
    "debug", "info", "warn", "error", "trace",
    "spans", "enter", "instrument",
    "hash", "copy_from_slice",
    # Go stdlib utilities
    "String", "Errorf", "Sprintf", "Printf", "Println", "Fprintf",
    "Len", "Cap", "Append", "Make", "Close", "Panic",
    # Python builtins
    "print", "str", "int", "float", "bool", "list", "dict", "set", "tuple",
    "len", "range", "enumerate", "zip", "map", "filter", "sorted", "reversed",
    "isinstance", "type", "repr", "format",
    # C/C++ stdlib
    "printf", "fprintf", "sprintf", "snprintf", "malloc", "free", "calloc",
    "realloc", "memcpy", "memset", "memcmp", "strlen", "strcpy", "strncpy",
    "sizeof", "offsetof",
    # Common TEE-safe calls (these don't cross boundaries)
    "to_hex", "from_hex", "encode", "decode",
})

# Security-relevant callee name substrings — always keep even if partially matching noise
_SECURITY_CALLEE_SUBSTRS = frozenset({
    "verify", "validate", "check", "sign", "encrypt", "decrypt",
    "attest", "quote", "seal", "unseal", "measure", "report",
    "ecall", "ocall", "enclave", "trusted", "key", "secret",
    "hash", "hmac", "digest", "nonce", "random",
    "authenticate", "authorize", "permission",
})

# Per-language patterns for actual function call sites
_CALL_SITE_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".rs": [
        re.compile(r"(\w+)::(\w+)\s*\("),           # Type::method(
        re.compile(r"self\.(\w+)\s*\("),             # self.method(
        re.compile(r"\.(\w+)\s*\("),                  # .method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare function(
    ],
    ".go": [
        re.compile(r"(\w+)\.(\w+)\s*\("),             # pkg.Func( or obj.Method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
    ".py": [
        re.compile(r"(\w+)\.(\w+)\s*\("),             # obj.method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
    ".ts": [
        re.compile(r"(\w+)\.(\w+)\s*\("),             # obj.method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
    ".c": [
        re.compile(r"(\w+)_(\w+)\s*\("),              # module_func(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
    ".cc": [  # C++ (also matched by .cpp below)
        re.compile(r"(\w+)::(\w+)\s*\("),             # Class::method(
        re.compile(r"(\w+)->(\w+)\s*\("),             # ptr->method(
        re.compile(r"\.(\w+)\s*\("),                  # obj.method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
    ".cpp": [
        re.compile(r"(\w+)::(\w+)\s*\("),             # Class::method(
        re.compile(r"(\w+)->(\w+)\s*\("),             # ptr->method(
        re.compile(r"\.(\w+)\s*\("),                  # obj.method(
        re.compile(r"(?:^|[^\w.])(\w+)\s*\("),        # bare func(
    ],
}


def _is_noise_callee(name: str) -> bool:
    """Check if a callee name is noise (common stdlib utility, not security-relevant)."""
    if name in _NOISE_CALLEE_NAMES:
        # Rescue if it has a security-relevant substring
        name_lower = name.lower()
        return not any(s in name_lower for s in _SECURITY_CALLEE_SUBSTRS)
    return False


def _extract_call_sites(file_path: Path, repo_path: Path) -> list[CallSite]:
    """Extract actual function call sites from a source file.

    Unlike _extract_references() which follows imports, this finds actual
    function invocations with their caller context.
    """
    suffix = file_path.suffix
    patterns = _CALL_SITE_PATTERNS.get(suffix, [])
    if not patterns:
        return []

    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        return []

    rel_path = str(file_path.relative_to(repo_path))
    func_patterns = _FUNCTION_PATTERNS.get(suffix, [])
    sites: list[CallSite] = []
    current_function = ""

    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Track current function context
        for fp in func_patterns:
            m = fp.match(stripped)
            if m and m.group(1) not in _CALL_KEYWORDS:
                current_function = m.group(1)
                break

        if not current_function:
            continue

        # Extract call sites from this line
        for pat in patterns:
            for match in pat.finditer(stripped):
                groups = match.groups()
                if len(groups) == 2:
                    # Type::method or obj.method pattern
                    mod, name = groups
                    if name in _CALL_KEYWORDS or mod in _CALL_KEYWORDS:
                        continue
                    if _is_noise_callee(name):
                        continue
                    sites.append(CallSite(
                        caller_function=current_function,
                        callee_name=name,
                        callee_module=mod,
                        line=line_no,
                        file=rel_path,
                    ))
                elif len(groups) == 1:
                    name = groups[0]
                    if name in _CALL_KEYWORDS or len(name) < 2:
                        continue
                    if _is_noise_callee(name):
                        continue
                    sites.append(CallSite(
                        caller_function=current_function,
                        callee_name=name,
                        line=line_no,
                        file=rel_path,
                    ))

    return sites


def build_caller_graph(
    repo_path: Path, zone_map: ZoneMap, max_files: int = 200,
) -> dict[str, list[CallSite]]:
    """Build a reverse caller graph: callee_key → [CallSite].

    Called once per pipeline run and reused for all findings.
    Keys are: bare function_name, Module::function, file::function.
    """
    caller_graph: dict[str, list[CallSite]] = {}
    file_count = 0

    for ext in _SOURCE_EXTENSIONS:
        for file_path in repo_path.rglob(f"*{ext}"):
            if file_count >= max_files:
                break
            parts = file_path.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            if _is_test_or_vendor(file_path):
                continue
            str_path = str(file_path)
            if "registry/src" in str_path or ".cargo" in str_path:
                continue

            sites = _extract_call_sites(file_path, repo_path)
            for site in sites:
                # Index by bare callee name
                for key in _callee_keys(site, repo_path):
                    caller_graph.setdefault(key, []).append(site)

            file_count += 1
        if file_count >= max_files:
            break

    logger.info(
        "Caller graph: %d files scanned, %d unique callee keys",
        file_count, len(caller_graph),
    )
    return caller_graph


def _callee_keys(site: CallSite, repo_path: Path) -> list[str]:
    """Generate lookup keys for a callee in the caller graph."""
    keys: list[str] = []
    bare = site.callee_name
    keys.append(bare)
    if site.callee_module:
        keys.append(f"{site.callee_module}::{bare}")
    # file-stem::function (e.g. "storage::from_pairs")
    stem = Path(site.file).stem
    keys.append(f"{stem}::{bare}")
    return keys


# Patterns for discovering trust boundary entry points
_ENTRY_POINT_PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    ".rs": [
        (re.compile(r"impl\s+(\w+)\s+for\s+(\w+)"), "rpc_handler"),
        (re.compile(r"#\[rpc\([^\)]*\)\]\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)"), "rpc_handler"),
        (re.compile(r"extern\s+\"C\"\s+fn\s+(\w+)"), "ecall"),
        (re.compile(r"fn\s+(ecall_\w+)\s*\("), "ecall"),
        (re.compile(r"fn\s+(ocall_\w+)\s*\("), "ocall"),
        (re.compile(r"fn\s+(init_\w+)\s*\("), "ecall"),
        (re.compile(r"fn\s+(dispatch_\w+)\s*\("), "rpc_handler"),
        (re.compile(r"fn\s+(handle_\w+)\s*\("), "rpc_handler"),
    ],
    ".go": [
        (re.compile(r"func\s+\((\w+)\s+\*?\w+\)\s+ServeHTTP"), "http_handler"),
        (re.compile(r"func\s+\((\w+)\s+\*?\w+\)\s+Handle"), "http_handler"),
        (re.compile(r"func\s+(main)\s*\("), "entry"),
    ],
    ".py": [
        (re.compile(r"def\s+(handle_\w+)\s*\("), "http_handler"),
        (re.compile(r"@app\.(?:route|get|post)\s*\([^)]*\)\s*def\s+(\w+)"), "http_handler"),
    ],
}


def discover_entry_points(
    repo_path: Path, zone_map: ZoneMap,
) -> list[EntryPoint]:
    """Discover trust boundary entry points using multiple strategies.

    Strategies:
    1. EDL-based: reuse zone_map.entry_points parsed from EDL files
    2. RPC handler traits: impl X for Y, #[rpc], dispatch/handle functions
    3. IPC patterns: extern "C" fn, ecall_/ocall_ prefixed functions
    4. Zone-crossing: public functions in MIXED-zone files
    """
    entry_points: list[EntryPoint] = []
    seen: set[str] = set()

    # Strategy 1: EDL-based entry points
    for edl_file, func_names in zone_map.entry_points.items():
        for func_name in func_names:
            ep_id = f"{edl_file}::{func_name}"
            if ep_id in seen:
                continue
            seen.add(ep_id)
            # Find which source file implements this function
            impl_file = _find_function_implementation(repo_path, func_name)
            zone = classify_code_location(impl_file, zone_map) if impl_file else TrustZone.UNKNOWN
            entry_points.append(EntryPoint(
                file=impl_file or edl_file,
                function=func_name,
                entry_type="ecall",
                zone=zone,
            ))

    # Strategy 2-3: Pattern-based discovery
    for ext, patterns in _ENTRY_POINT_PATTERNS.items():
        for file_path in repo_path.rglob(f"*{ext}"):
            parts = file_path.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            if _is_test_or_vendor(file_path):
                continue

            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = str(file_path.relative_to(repo_path))
            zone = classify_code_location(rel, zone_map)

            for pat, entry_type in patterns:
                for match in pat.finditer(content):
                    func_name = match.group(match.lastindex or 1)
                    ep_id = f"{rel}::{func_name}"
                    if ep_id in seen:
                        continue
                    seen.add(ep_id)
                    # Find line number
                    line_no = None
                    for i, line in enumerate(content.splitlines(), 1):
                        if func_name in line:
                            line_no = i
                            break
                    entry_points.append(EntryPoint(
                        file=rel,
                        function=func_name,
                        entry_type=entry_type,
                        zone=zone,
                        line=line_no,
                    ))

    # Strategy 4: Public functions in MIXED-zone files
    for rel_path, zone in zone_map.zones.items():
        if zone != TrustZone.MIXED:
            continue
        abs_path = repo_path / rel_path
        if not abs_path.exists():
            continue
        func_names = _extract_function_names(abs_path)
        for fn in func_names:
            ep_id = f"{rel_path}::{fn}"
            if ep_id in seen:
                continue
            seen.add(ep_id)
            entry_points.append(EntryPoint(
                file=rel_path,
                function=fn,
                entry_type="zone_crossing",
                zone=TrustZone.MIXED,
            ))

    logger.info(
        "Entry points discovered: %d (%d ecall, %d rpc_handler, %d other)",
        len(entry_points),
        sum(1 for e in entry_points if e.entry_type == "ecall"),
        sum(1 for e in entry_points if e.entry_type == "rpc_handler"),
        sum(1 for e in entry_points if e.entry_type not in ("ecall", "rpc_handler")),
    )
    return entry_points


def _find_function_implementation(repo_path: Path, func_name: str) -> str | None:
    """Find the file that implements a named function."""
    for ext in _SOURCE_EXTENSIONS:
        for file_path in repo_path.rglob(f"*{ext}"):
            parts = file_path.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue
            # Check for function definition
            if re.search(rf"(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(func_name)}\s*\(", content):
                return str(file_path.relative_to(repo_path))
            if re.search(rf"def\s+{re.escape(func_name)}\s*\(", content):
                return str(file_path.relative_to(repo_path))
            if re.search(rf"func\s+{re.escape(func_name)}\s*\(", content):
                return str(file_path.relative_to(repo_path))
    return None


def trace_invocation_chain(
    sink_file: str,
    sink_function: str,
    caller_graph: dict[str, list[CallSite]],
    entry_points: list[EntryPoint],
    zone_map: ZoneMap,
    repo_path: Path,
    max_depth: int = 6,
) -> InvocationChain | None:
    """Trace backward from a sink to a trust boundary entry point via BFS.

    Uses a priority queue that prefers cross-zone and cross-file callers,
    producing genuine cross-file trust boundary traces. Retries with relaxed
    constraints if initial result is intra-file only.
    """
    # Build entry point lookup
    ep_lookup: dict[str, EntryPoint] = {}
    for ep in entry_points:
        ep_lookup[ep.function] = ep
        stem = Path(ep.file).stem
        ep_lookup[f"{stem}::{ep.function}"] = ep

    sink_zone = classify_code_location(sink_file, zone_map)
    sink_stem = Path(sink_file).stem

    def _score_caller(caller: CallSite, current_file: str) -> int:
        caller_zone = classify_code_location(caller.file, zone_map)
        current_zone = classify_code_location(current_file, zone_map)
        score = 0
        if caller.file != current_file:
            score += 2  # Cross-file
        if (
            caller_zone != current_zone
            and caller_zone != TrustZone.UNKNOWN
            and current_zone != TrustZone.UNKNOWN
        ):
            score += 3  # Cross-zone
        if caller_zone == TrustZone.MIXED:
            score += 1  # Potential boundary area
        return score

    def _run_bfs(
        depth_limit: int,
        allowed_ep_funcs: set[str] | None = None,
        penalized_files: set[str] | None = None,
    ) -> InvocationChain | None:
        """Priority-queue BFS backward from sink."""
        filtered_lookup = ep_lookup
        if allowed_ep_funcs is not None:
            filtered_lookup = {
                k: v for k, v in ep_lookup.items() if v.function in allowed_ep_funcs
            }

        visited: set[str] = set()
        # (-score, tiebreaker, file, func, hops) — negate score for max-heap
        counter = 0
        queue: list[tuple[int, int, str, str, list[CallSite]]] = []
        heapq.heappush(queue, (0, counter, sink_file, sink_function, []))
        counter += 1

        while queue:
            neg_score, _, current_file, current_func, hops = heapq.heappop(queue)
            state_key = f"{current_file}::{current_func}"
            if state_key in visited or len(hops) >= depth_limit:
                continue
            visited.add(state_key)

            # Check if current function is a known entry point
            if current_func in filtered_lookup:
                ep = filtered_lookup[current_func]
                return InvocationChain(
                    entry_point=ep,
                    hops=list(reversed(hops)),
                    sink_file=sink_file,
                    sink_function=sink_function,
                    zones_crossed=_count_zone_crossings(hops, zone_map),
                    complete=True,
                    confidence="confirmed",
                )

            # Look up callers of current function
            callers: list[CallSite] = []
            for key in (current_func, f"{sink_stem}::{current_func}"):
                callers.extend(caller_graph.get(key, []))

            for caller in callers:
                if caller.file == current_file and caller.caller_function == current_func:
                    continue  # Skip self-references
                caller_key = f"{caller.file}::{caller.caller_function}"
                if caller_key in visited:
                    continue

                new_hops = hops + [caller]

                # Check if caller is an entry point
                if caller.caller_function in filtered_lookup:
                    ep = filtered_lookup[caller.caller_function]
                    return InvocationChain(
                        entry_point=ep,
                        hops=list(reversed(new_hops)),
                        sink_file=sink_file,
                        sink_function=sink_function,
                        zones_crossed=_count_zone_crossings(new_hops, zone_map),
                        complete=True,
                        confidence="confirmed",
                    )

                score = _score_caller(caller, current_file)
                if penalized_files and caller.file in penalized_files:
                    score -= 10  # Strong penalty for retrying same files
                heapq.heappush(
                    queue,
                    (-score, counter, caller.file, caller.caller_function, new_hops),
                )
                counter += 1

        return None

    def _is_cross_file(chain: InvocationChain) -> bool:
        files = {hop.file for hop in chain.hops}
        if chain.entry_point:
            files.add(chain.entry_point.file)
        return len(files) >= 2

    # --- Attempt 1: Standard priority BFS ---
    chain = _run_bfs(max_depth)

    if chain is not None and chain.complete:
        if _is_cross_file(chain):
            return chain

        # --- Retry 1: Deeper search, penalize same-file callers ---
        bad_files = {hop.file for hop in chain.hops}
        if chain.entry_point:
            bad_files.add(chain.entry_point.file)
        logger.warning(
            "Intra-file chain for %s::%s (all in %s), retrying with deeper search",
            sink_file, sink_function, next(iter(bad_files), sink_file),
        )
        chain2 = _run_bfs(max_depth + 4, penalized_files=bad_files)
        if chain2 is not None and chain2.complete and _is_cross_file(chain2):
            return chain2

        # --- Retry 2: Only accept entry points in different zone from sink ---
        alt_ep_funcs = {
            ep.function
            for ep in entry_points
            if classify_code_location(ep.file, zone_map) != sink_zone
        }
        if alt_ep_funcs:
            alt_chain = _run_bfs(
                max_depth + 4,
                allowed_ep_funcs=alt_ep_funcs,
                penalized_files=bad_files,
            )
            if alt_chain is not None and alt_chain.complete and _is_cross_file(alt_chain):
                return alt_chain

        # Final fallback — log tracing gap
        logger.warning(
            "Tracing gap: could not find cross-file chain for %s::%s after retries. "
            "Zone map or caller graph may be missing edges.",
            sink_file, sink_function,
        )
        return chain

    # No chain found at all
    return chain or InvocationChain(
        entry_point=None,
        hops=[],
        sink_file=sink_file,
        sink_function=sink_function,
        complete=False,
        confidence="no_chain",
    )


def _count_zone_crossings(hops: list[CallSite], zone_map: ZoneMap) -> int:
    """Count trust boundary crossings in a chain of call sites."""
    crossings = 0
    prev_zone: TrustZone | None = None
    for hop in hops:
        zone = classify_code_location(hop.file, zone_map)
        if prev_zone and prev_zone != TrustZone.UNKNOWN and zone != TrustZone.UNKNOWN:
            if prev_zone != zone:
                crossings += 1
        prev_zone = zone
    return crossings


def format_invocation_chain(chain: InvocationChain, zone_map: ZoneMap | None = None) -> str:
    """Format an InvocationChain as human-readable text for LLM prompts."""
    if chain.confidence == "no_chain":
        return "[No invocation chain traced to trust boundary]"

    status = "COMPLETE" if chain.complete else "PARTIAL"
    boundary_note = f", {chain.zones_crossed} boundary crossing{'s' if chain.zones_crossed != 1 else ''}"
    lines: list[str] = []
    lines.append(f"{status} invocation chain ({len(chain.hops)} hops{boundary_note}):")

    if chain.entry_point:
        ep = chain.entry_point
        zone_label = ep.zone.value.upper()
        loc = f":{ep.line}" if ep.line else ""
        lines.append(
            f"  1. [{zone_label}] {ep.file}{loc}  {ep.function} ({ep.entry_type} entry)"
        )

    for i, hop in enumerate(chain.hops):
        hop_num = i + 2 if chain.entry_point else i + 1
        if zone_map:
            zone = classify_code_location(hop.file, zone_map)
        else:
            zone = TrustZone.UNKNOWN
        zone_label = zone.value.upper()
        arrow = "→ " if i == 0 and chain.entry_point else "  "
        mod = f"{hop.callee_module}::" if hop.callee_module else ""
        lines.append(
            f"  {hop_num}. [{zone_label}] {hop.file}:{hop.line}  {arrow}{mod}{hop.callee_name}"
        )

    lines.append(
        f"  SINK: {chain.sink_file} :: {chain.sink_function}"
    )
    lines.append(f"  Confidence: {chain.confidence}")

    return "\n".join(lines)


def compute_chain_confidence(chain: InvocationChain | None) -> str:
    """Compute chain confidence for use in finding metadata."""
    if chain is None:
        return "no_chain"
    return chain.confidence
