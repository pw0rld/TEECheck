"""Pluggable TEE manifest parsers for authoritative zone classification.

Each parser extracts trusted files, entry points, and TEE configuration
from platform-specific manifest formats. All output the same ParsedManifest
structure for merging into the ZoneMap.

Supported platforms:
- Gramine (.manifest, .manifest.template)
- Open Enclave EDL (.edl)
- Dockerfile (TEE base image detection)
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class EntryPoint:
    """A trust boundary entry point extracted from a manifest."""

    function: str
    file: str = ""
    entry_type: str = ""  # "ecall", "ocall", "binary_entrypoint", etc.
    zone: str = "trusted"


@dataclass
class ParsedManifest:
    """Normalized output from any manifest parser."""

    trusted_files: list[str] = field(default_factory=list)
    untrusted_files: list[str] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    source: str = ""  # e.g. "gramine_manifest", "edl", "dockerfile"
    platform: str = ""  # e.g. "gramine", "sgx", "nitro"


class ManifestParser(ABC):
    """Base class for TEE manifest parsers."""

    @abstractmethod
    def parse(self, repo_path: Path) -> ParsedManifest | None:
        """Parse manifest files in the repo. Returns None if no manifest found."""
        ...


class GramineManifestParser(ManifestParser):
    """Parse Gramine .manifest and .manifest.template files.

    Extracts:
    - libos.entrypoint → binary entry point
    - fs.mounts with type="encrypted" → trusted file paths
    - trusted_files list → trusted file paths
    - sgx section → confirms SGX platform
    """

    def parse(self, repo_path: Path) -> ParsedManifest | None:
        manifest_files = list(repo_path.rglob("*.manifest")) + list(
            repo_path.rglob("*.manifest.template")
        )
        # Skip files in output/build/vendor directories
        skip_parts = {"output", "build", "vendor", "target", ".cargo", "node_modules"}
        manifest_files = [
            f
            for f in manifest_files
            if not any(p in skip_parts for p in f.relative_to(repo_path).parts)
        ]

        if not manifest_files:
            return None

        trusted_files: list[str] = []
        entry_points: list[EntryPoint] = []
        platform = ""

        for mf in manifest_files:
            try:
                content = mf.read_text(errors="ignore")
            except OSError:
                continue

            # Extract entrypoint from [libos] section
            ep_match = re.search(r'^\s*entrypoint\s*=\s*"([^"]+)"', content, re.MULTILINE)
            if ep_match:
                entry_binary = ep_match.group(1)
                # Find the binary in the repo
                for candidate in repo_path.rglob(entry_binary):
                    rel = str(candidate.relative_to(repo_path))
                    entry_points.append(EntryPoint(
                        function=entry_binary,
                        file=rel,
                        entry_type="binary_entrypoint",
                        zone="trusted",
                    ))
                    trusted_files.append(rel)
                    break
                # Also add as a generic entry point if binary not found
                if not any(ep.function == entry_binary for ep in entry_points):
                    entry_points.append(EntryPoint(
                        function=entry_binary,
                        entry_type="binary_entrypoint",
                        zone="trusted",
                    ))

            # Extract encrypted mount paths (these are trusted)
            for mount_match in re.finditer(
                r'type\s*=\s*"encrypted"[^}]*?path\s*=\s*"([^"]+)"', content, re.DOTALL
            ):
                path = mount_match.group(1)
                trusted_files.append(path)

            # Also check reverse order (path before type)
            for mount_block in re.finditer(r'\[\[fs\.mounts\]\](.*?)(?=\[\[fs\.mounts\]\]|\[)', content, re.DOTALL):
                block = mount_block.group(1)
                if 'type = "encrypted"' in block or 'type="encrypted"' in block:
                    path_match = re.search(r'path\s*=\s*"([^"]+)"', block)
                    if path_match:
                        path = path_match.group(1)
                        if path not in trusted_files:
                            trusted_files.append(path)

            # Extract trusted_files list
            for tf_match in re.finditer(r'trusted_files\s*=\s*\[(.*?)\]', content, re.DOTALL):
                for file_match in re.finditer(r'"file:([^"]+)"', tf_match.group(1)):
                    tf = file_match.group(1)
                    # Strip Jinja2 template variables for path matching
                    clean_path = re.sub(r'\{\{.*?\}\}', '*', tf)
                    if clean_path not in trusted_files:
                        trusted_files.append(clean_path)

            # Detect platform
            if "[sgx]" in content:
                platform = "sgx"
            elif "[tdx]" in content:
                platform = "tdx"

        if not trusted_files and not entry_points:
            return None

        return ParsedManifest(
            trusted_files=trusted_files,
            entry_points=entry_points,
            source="gramine_manifest",
            platform=platform or "gramine",
        )


class EDLParser(ManifestParser):
    """Parse Open Enclave EDL (.edl) files.

    Extracts:
    - trusted {} section → ECALL function names and parameter hints
    - untrusted {} section → OCALL function names
    """

    def parse(self, repo_path: Path) -> ParsedManifest | None:
        skip_parts = {"output", "build", "vendor", "target", ".cargo", "node_modules"}
        edl_files = [
            f
            for f in repo_path.rglob("*.edl")
            if not any(p in skip_parts for p in f.relative_to(repo_path).parts)
        ]

        if not edl_files:
            return None

        entry_points: list[EntryPoint] = []
        trusted_files: list[str] = []

        for edl in edl_files:
            try:
                content = edl.read_text(errors="ignore")
            except OSError:
                continue

            rel = str(edl.relative_to(repo_path))
            trusted_files.append(rel)

            # Extract trusted {} (ECALL) functions
            trusted_block = re.search(r'trusted\s*\{(.*?)\}', content, re.DOTALL)
            if trusted_block:
                for func_match in re.finditer(
                    r'(?:public\s+)?\w+\s+(\w+)\s*\(', trusted_block.group(1)
                ):
                    func_name = func_match.group(1)
                    entry_points.append(EntryPoint(
                        function=func_name,
                        file=rel,
                        entry_type="ecall",
                        zone="trusted",
                    ))

            # Extract untrusted {} (OCALL) functions
            untrusted_block = re.search(r'untrusted\s*\{(.*?)\}', content, re.DOTALL)
            if untrusted_block:
                for func_match in re.finditer(
                    r'(?:public\s+)?\w+\s+(\w+)\s*\(', untrusted_block.group(1)
                ):
                    func_name = func_match.group(1)
                    entry_points.append(EntryPoint(
                        function=func_name,
                        file=rel,
                        entry_type="ocall",
                        zone="untrusted",
                    ))

        if not entry_points:
            return None

        return ParsedManifest(
            trusted_files=trusted_files,
            entry_points=entry_points,
            source="edl",
            platform="sgx",
        )


class DockerfileParser(ManifestParser):
    """Parse Dockerfiles for TEE-related build configurations.

    Detects:
    - TEE-specific base images (openenclave, aws-nitro, gramine, etc.)
    - Enclave binary build targets from cargo/cc commands
    """

    _TEE_BASE_IMAGE_PATTERNS = [
        re.compile(r"openenclave", re.IGNORECASE),
        re.compile(r"aws-nitro|nitro-enclaves", re.IGNORECASE),
        re.compile(r"gramine", re.IGNORECASE),
        re.compile(r"occlum", re.IGNORECASE),
        re.compile(r"apache/incubator-teaclave", re.IGNORECASE),
    ]

    _ENCLAVE_BUILD_PATTERNS = [
        re.compile(r"cargo\s+build.*--bin\s+(\S+)", re.IGNORECASE),
        re.compile(r"(?:make|cmake).*--target\s+(\S+)", re.IGNORECASE),
    ]

    def parse(self, repo_path: Path) -> ParsedManifest | None:
        skip_parts = {"output", "vendor", "node_modules"}
        dockerfiles = [
            f
            for f in repo_path.rglob("Dockerfile*")
            if not any(p in skip_parts for p in f.relative_to(repo_path).parts)
        ]

        if not dockerfiles:
            return None

        trusted_files: list[str] = []
        entry_points: list[EntryPoint] = []
        platform = ""

        for df in dockerfiles:
            try:
                content = df.read_text(errors="ignore")
            except OSError:
                continue

            # Check for TEE base images
            for from_match in re.finditer(r'FROM\s+(\S+)', content):
                image = from_match.group(1)
                for pattern in self._TEE_BASE_IMAGE_PATTERNS:
                    if pattern.search(image):
                        platform = "tee-container"
                        break

            # Extract enclave binary build targets
            for build_match in re.finditer(
                r"cargo\s+build.*--bin\s+(\S+)", content
            ):
                binary = build_match.group(1)
                entry_points.append(EntryPoint(
                    function=binary,
                    file=str(df.relative_to(repo_path)),
                    entry_type="build_target",
                    zone="trusted",
                ))

        if not platform and not entry_points:
            return None

        return ParsedManifest(
            trusted_files=trusted_files,
            entry_points=entry_points,
            source="dockerfile",
            platform=platform,
        )


def parse_all_manifests(repo_path: Path) -> ParsedManifest | None:
    """Try all available manifest parsers in priority order.

    Priority: Gramine → EDL → Dockerfile
    Returns the first successful parse, or None if no manifest found.
    """
    parsers: list[ManifestParser] = [
        GramineManifestParser(),
        EDLParser(),
        DockerfileParser(),
    ]

    results: list[ParsedManifest] = []
    for parser in parsers:
        try:
            result = parser.parse(repo_path)
            if result:
                results.append(result)
                logger.info(
                    "Manifest parsed: %s (%d trusted files, %d entry points)",
                    result.source,
                    len(result.trusted_files),
                    len(result.entry_points),
                )
        except Exception:
            logger.debug("Manifest parser %s failed", type(parser).__name__, exc_info=True)

    if not results:
        return None

    # Merge all results (Gramine takes priority for conflicts)
    merged = ParsedManifest(
        trusted_files=[],
        entry_points=[],
        source=", ".join(r.source for r in results),
        platform=results[0].platform,
    )
    seen_funcs: set[str] = set()
    seen_files: set[str] = set()
    for result in results:
        for f in result.trusted_files:
            if f not in seen_files:
                merged.trusted_files.append(f)
                seen_files.add(f)
        for ep in result.entry_points:
            if ep.function not in seen_funcs:
                merged.entry_points.append(ep)
                seen_funcs.add(ep.function)

    return merged
