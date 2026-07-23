"""Stage 5b: Deep Verification — LLM-powered finding verification.

Expanded into sub-phases reflecting the complexity of deep-verification.md:
5b.1: SARIF clustering
5b.2: Code context assembly
5b.3: Per-cluster LLM verification (parallel)
5b.4: Self-validation loop
5b.5: Severity assignment
5b.6: Output assembly
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage5bInput, Stage5bOutput
from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt, load_taxonomy
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.finding import Finding, Severity, Confidence, TrustPathTier, CodeLocation, TraceHop
from tee_audit.models.invariant import InvariantFamily
from tee_audit.models.triage import GradedFinding
from tee_audit.models.unknown import Unknown
from tee_audit.utils.call_graph import (
    apply_project_role_to_zones,
    build_caller_graph,
    build_fingerprint_map,
    build_zone_map,
    classify_code_location,
    discover_entry_points,
    discover_related_files,
    format_call_chain_for_prompt,
    format_invocation_chain,
    infer_project_tee_role,
    lookup_zone_source,
    overlay_manifest_zones,
    trace_call_chain,
    trace_invocation_chain,
    CallSite,
    EntryPoint,
    InvocationChain,
    ProjectTEERole,
    TrustZone,
    ZoneMap,
)

logger = logging.getLogger(__name__)

_MAX_API_RETRIES = 3
_INITIAL_BACKOFF_SECONDS = 5


class FindingResponse(BaseModel):
    """Wrapper for a single LLM-verified finding."""

    finding: Finding | None = None
    is_unknown: bool = False
    unknown_description: str = ""


class FindingsBatchResponse(BaseModel):
    """Wrapper for a batch of findings from one cluster."""

    findings: list[Finding]
    unknowns: list[Unknown]


# --- Sub-phase 5b.1: Clustering ---

def _cluster_by_invariant_and_file(
    graded_findings: list[GradedFinding],
) -> dict[str, list[GradedFinding]]:
    """Cluster graded findings by (invariant_id, file) pairs."""
    clusters: dict[str, list[GradedFinding]] = defaultdict(list)
    for gf in graded_findings:
        file_path = gf.code_location.split(":")[0] if ":" in gf.code_location else gf.code_location
        key = f"{gf.invariant_id}::{file_path}"
        clusters[key].append(gf)
    return dict(clusters)


# --- Sub-phase 5b.2: Code context assembly ---

def _read_code_context(file_path: Path, line: int | None, context_lines: int = 80) -> str:
    """Read source code around a location with context window."""
    if not file_path.exists():
        return f"[File not found: {file_path}]"

    try:
        lines = file_path.read_text(errors="ignore").splitlines()
        if line is None:
            # Return first N lines
            return "\n".join(lines[:context_lines * 2])

        start = max(0, line - context_lines)
        end = min(len(lines), line + context_lines)
        return "\n".join(
            f"{i + 1:4d} | {lines[i]}"
            for i in range(start, end)
        )
    except (OSError, ValueError) as e:
        return f"[Error reading {file_path}: {e}]"


def _is_test_file(file_path: str) -> bool:
    """Check if a file path indicates test/example/benchmark code."""
    path_lower = file_path.lower().replace("\\", "/")
    test_dirs = {"test/", "tests/", "testing/", "examples/", "benches/"}
    test_suffixes = {"_test.rs", "_test.go", "_test.py", "_test.ts"}
    if any(d in path_lower for d in test_dirs):
        return True
    filename = path_lower.rsplit("/", 1)[-1]
    if any(filename.endswith(s) for s in test_suffixes):
        return True
    if "/bin/" in path_lower and "test" in path_lower:
        return True
    return False


# --- Sub-phase 5b.3: Per-cluster LLM verification ---

import re as _re

_FN_PATTERNS: list[_re.Pattern[str]] = [
    _re.compile(r'\bfn\s+(\w+)'),          # Rust
    _re.compile(r'\bdef\s+(\w+)'),          # Python
    _re.compile(r'\bfunc\s+(\w+)'),         # Go
    _re.compile(r'\b(\w+)\s*\([^)]*\)\s*\{'),  # C/C++/Java
]


def _extract_enclosing_function(repo_path: Path, file_rel: str, line_num: int | None) -> str | None:
    """Walk backward from line_num in the source file to find the enclosing function."""
    if not file_rel or file_rel == "unknown":
        return None
    target = repo_path / file_rel
    if not target.exists():
        return None
    try:
        lines = target.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    start = (line_num or len(lines)) - 1
    start = min(start, len(lines) - 1)
    # Walk backward up to 80 lines looking for a function definition
    for i in range(start, max(start - 80, -1), -1):
        line = lines[i]
        for pat in _FN_PATTERNS:
            m = pat.search(line)
            if m:
                return m.group(1)
    return None


def _backfill_locations(
    findings: list[Finding],
    graded: list[GradedFinding],
) -> list[Finding]:
    """Fill empty code_locations from triage-level GradedFinding data."""
    # Build quick lookup: invariant_id -> list of GradedFinding code_locations
    triage_locs: dict[str, list[tuple[str, int | None]]] = {}
    for gf in graded:
        triage_locs.setdefault(gf.invariant_id, []).append(
            (gf.code_location.split(":")[0],
             int(gf.code_location.split(":")[1]) if ":" in gf.code_location and gf.code_location.split(":")[1].isdigit() else None)
        )

    result = []
    backfilled = 0
    for f in findings:
        if f.code_locations:
            result.append(f)
            continue
        # No locations from LLM — use triage data for same invariant
        backfilled += 1
        locs = triage_locs.get(f.invariant_id, [])
        if locs:
            result.append(f.model_copy(update={
                "code_locations": [
                    CodeLocation(file=file, line=line) for file, line in locs[:3]
                ],
            }))
        else:
            result.append(f)
    if backfilled:
        logger.warning("Backfilled code_locations from triage data for %d findings", backfilled)
    return result


def _inject_chain_into_finding(
    finding: Finding,
    chain: InvocationChain,
    zone_map: ZoneMap,
    caller_graph: dict | None = None,
) -> Finding:
    """Post-process a finding to inject pre-traced invocation chain data.

    If the LLM already filled trust_boundary_trace, keep it.
    Otherwise, convert the deterministically traced chain into
    TraceHop entries and prose for the report.
    """
    if finding.trust_boundary_trace and len(finding.trust_boundary_trace) > 0:
        return finding
    if not finding.is_tee_relevant or finding.dismissed:
        return finding

    trace_hops: list[TraceHop] = []
    if chain.entry_point:
        ep = chain.entry_point
        ep_source = lookup_zone_source(ep.file, zone_map)
        # Use zone_map (Gramine-aware) instead of ep.zone (pre-Gramine heuristic)
        ep_zone = classify_code_location(ep.file, zone_map)
        trace_hops.append(TraceHop(
            source_zone=ep_zone.value,
            crossing_point=f"{ep.file}:{ep.line or '?'}",
            sink_zone=ep_zone.value,
            verification_status="present" if chain.complete else "unknown",
            description=f"Entry point: {ep.function} ({ep.entry_type})",
            caller_function=ep.function,
            callee_name=ep.function,
            file=ep.file,
            line=ep.line,
            crosses_boundary=False,
            zone_source=ep_source,
        ))

    for hop in chain.hops:
        hop_zone = classify_code_location(hop.file, zone_map)
        hop_source = lookup_zone_source(hop.file, zone_map)
        trace_hops.append(TraceHop(
            source_zone=hop_zone.value,
            crossing_point=f"{hop.file}:{hop.line}",
            sink_zone=hop_zone.value,
            verification_status="present",
            description=f"Call to {hop.callee_module + '::' if hop.callee_module else ''}{hop.callee_name}",
            caller_function=hop.caller_function,
            callee_name=hop.callee_name,
            callee_module=hop.callee_module,
            file=hop.file,
            line=hop.line,
            crosses_boundary=False,
            zone_source=hop_source,
        ))

    # Post-process: mark boundary crossings between adjacent hops
    # Only mark as boundary crossing if files are DIFFERENT (same file = same zone)
    for i in range(1, len(trace_hops)):
        prev_file = trace_hops[i - 1].file
        cur_file = trace_hops[i].file
        if (trace_hops[i - 1].source_zone != trace_hops[i].source_zone
                and prev_file and cur_file and prev_file != cur_file):
            trace_hops[i] = trace_hops[i].model_copy(update={
                "source_zone": trace_hops[i - 1].sink_zone,
                "crosses_boundary": True,
            })

    prose_parts: list[str] = []
    # Build zone label helper
    def _zone_label(z: str) -> str:
        return "ENCLAVE (TRUSTED)" if z == "trusted" else "HOST (UNTRUSTED)" if z == "untrusted" else f"MIXED ({z})"

    if chain.entry_point:
        ep = chain.entry_point
        prose_parts.append(
            f"Entry point: {ep.function}() in {_zone_label(ep.zone.value)} at {ep.file} ({ep.entry_type})"
        )
    prev_zone = chain.entry_point.zone.value if chain.entry_point else None
    for hop in chain.hops:
        hop_zone = classify_code_location(hop.file, zone_map)
        zone_label = _zone_label(hop_zone.value)
        crosses = hop_zone.value != prev_zone and prev_zone is not None
        if crosses:
            prose_parts.append(
                f"BOUNDARY CROSSING: {_zone_label(prev_zone)} -> {_zone_label(hop_zone.value)} at "
                f"{hop.file}:{hop.line} via {hop.callee_name}()"
            )
        else:
            prose_parts.append(
                f"flows through {hop.callee_name}() in {zone_label} at {hop.file}:{hop.line}"
            )
        prev_zone = hop_zone.value
    prose_parts.append(
        f"Sink: {chain.sink_file}::{chain.sink_function} "
        f"(chain: {'complete' if chain.complete else 'partial'}, {chain.zones_crossed} boundary crossings)"
    )
    prose = "; ".join(prose_parts) + "."

    return finding.model_copy(update={
        "trust_boundary_trace": trace_hops,
        "trust_boundary_prose": prose,
    })


def _find_host_caller_via_grep(
    enclave_func: str,
    zone_map: ZoneMap,
    repo_path: Path,
) -> TraceHop | None:
    """Search HOST files for references to an enclave function name.

    Fallback when the caller graph lacks pRPC cross-boundary edges.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["grep", "-rn", "--include=*.rs", "-w", enclave_func, str(repo_path)],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            abs_path, line_str = parts[0], parts[1]
            if not line_str.isdigit():
                continue
            line_num = int(line_str)
            rel_path = abs_path.replace(str(repo_path) + "/", "").replace(str(repo_path), "")
            if not rel_path:
                continue
            zone = classify_code_location(rel_path, zone_map)
            if zone.value == "untrusted":
                func_name = _extract_enclosing_function(repo_path, rel_path, line_num)
                return TraceHop(
                    source_zone="untrusted",
                    crossing_point=f"{rel_path}:{line_num}",
                    sink_zone="untrusted",
                    verification_status="present",
                    description=f"HOST references enclave method: {func_name or '?'}() in {rel_path}:{line_num} -> {enclave_func}()",
                    caller_function=func_name or rel_path,
                    callee_name=enclave_func,
                    file=rel_path,
                    line=line_num,
                    crosses_boundary=False,
                    zone_source="grep_search",
                )
    except Exception:
        pass
    return None


def _inject_host_caller_context(
    finding: Finding,
    caller_graph: dict[str, list],
    zone_map: ZoneMap,
    repo_path: Path,
) -> Finding:
    """For enclave findings without HOST-side context, find and inject HOST callers.

    Uses two strategies:
    1. Direct function calls found in caller_graph
    2. pRPC/HTTP calls found via grep search in HOST files
    """
    if not finding.is_tee_relevant or finding.dismissed:
        return finding
    if not finding.code_locations:
        return finding

    # Check if already has a genuine HOST→ENCLAVE boundary (untrusted hop followed by trusted)
    if finding.trust_boundary_trace:
        for i, h in enumerate(finding.trust_boundary_trace):
            if h.source_zone == "untrusted" and i + 1 < len(finding.trust_boundary_trace):
                next_h = finding.trust_boundary_trace[i + 1]
                if next_h.source_zone == "trusted" and h.file and next_h.file and h.file != next_h.file:
                    return finding

    loc = finding.code_locations[0]
    sink_zone = classify_code_location(loc.file, zone_map)
    if sink_zone.value != "trusted":
        return finding

    sink_func = _extract_enclosing_function(repo_path, loc.file, loc.line)
    if not sink_func:
        return finding

    # Strategy 1: caller graph
    host_caller: TraceHop | None = None
    for key in (sink_func, f"{Path(loc.file).stem}::{sink_func}"):
        sites = caller_graph.get(key, [])
        for s in sites:
            szone = classify_code_location(s.file, zone_map)
            if szone.value == "untrusted":
                host_caller = TraceHop(
                    source_zone="untrusted",
                    crossing_point=f"{s.file}:{s.line}",
                    sink_zone="untrusted",
                    verification_status="present",
                    description=f"HOST caller: {s.caller_function}() in {s.file}:{s.line}",
                    caller_function=s.caller_function,
                    callee_name=sink_func,
                    file=s.file,
                    line=s.line,
                    crosses_boundary=False,
                    zone_source="caller_graph",
                )
                break
        if host_caller:
            break

    # Strategy 2: grep for function name in HOST files (pRPC fallback)
    if not host_caller:
        host_caller = _find_host_caller_via_grep(sink_func, zone_map, repo_path)

    if not host_caller:
        return finding

    # Prepend HOST hop, mark first enclave hop as boundary crossing
    existing = list(finding.trust_boundary_trace or [])
    new_trace = [host_caller]
    for i, hop in enumerate(existing):
        if i == 0:
            new_trace.append(hop.model_copy(update={
                "crosses_boundary": True,
                "source_zone": "trusted",
            }))
        else:
            new_trace.append(hop)

    host_label = f"{host_caller.file}:{host_caller.caller_function}()"
    enclave_label = f"{loc.file}:{sink_func}()"
    prose = (
        f"HOST (UNTRUSTED): {host_label} "
        f"calls ENCLAVE (TRUSTED): {enclave_label} "
        f"via pRPC boundary. "
    )
    if finding.trust_boundary_prose:
        prose += finding.trust_boundary_prose

    return finding.model_copy(update={
        "trust_boundary_trace": new_trace,
        "trust_boundary_prose": prose,
    })


def _correct_trace_zones(
    finding: Finding,
    zone_map: ZoneMap,
) -> Finding:
    """Post-process trust_boundary_trace to correct LLM-filled zone labels.

    The LLM often mislabels enclave files as 'untrusted' because it lacks
    the zone_map. This function reclassifies all hop zones from the actual
    file zones and recalculates boundary crossings.
    """
    if not finding.trust_boundary_trace:
        return finding

    corrected = []
    for hop in finding.trust_boundary_trace:
        if hop.file and hop.file != "unknown":
            file_zone = classify_code_location(hop.file, zone_map)
            corrected.append(hop.model_copy(update={
                "source_zone": file_zone.value,
                "sink_zone": file_zone.value,
                "zone_source": lookup_zone_source(hop.file, zone_map),
            }))
        else:
            corrected.append(hop)

    # First hop never crosses a boundary (nothing before it)
    if corrected:
        corrected[0] = corrected[0].model_copy(update={"crosses_boundary": False})

    # Recalculate boundary crossings between adjacent hops
    for i in range(1, len(corrected)):
        prev = corrected[i - 1]
        cur = corrected[i]
        prev_file = prev.file or ""
        cur_file = cur.file or ""
        if (prev.sink_zone != cur.source_zone
                and prev_file and cur_file and prev_file != cur_file):
            corrected[i] = corrected[i].model_copy(update={
                "crosses_boundary": True,
            })
        else:
            corrected[i] = corrected[i].model_copy(update={
                "crosses_boundary": False,
            })

    return finding.model_copy(update={
        "trust_boundary_trace": corrected,
    })


def _read_source_snippet(repo_path: Path, file_rel: str, line_num: int | None, context: int = 10) -> str | None:
    """Read a source snippet around a line for use as code_location snippet."""
    target = repo_path / file_rel
    if not target.exists():
        # Try fuzzy match by filename
        filename = file_rel.split("/")[-1]
        for match in repo_path.rglob(filename):
            if match.is_file():
                target = match
                break
        else:
            return None
    try:
        lines = target.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    center = (line_num or len(lines)) - 1
    center = min(max(center, 0), len(lines) - 1)
    start = max(0, center - context)
    end = min(len(lines), center + context + 1)
    parts = []
    for i in range(start, end):
        marker = ">>>" if i == center else "   "
        parts.append(f"{marker} {i + 1:4d} | {lines[i]}")
    return "\n".join(parts)


def _grep_in_zone(
    pattern: str,
    repo_path: Path,
    zone_map: ZoneMap,
    target_zone: str,
    max_results: int = 3,
) -> list[tuple[str, int, str]]:
    """Search for a pattern in files of a specific zone. Returns (file, line, matching_line_text)."""
    import subprocess
    results = []
    try:
        proc = subprocess.run(
            ["grep", "-rn", "--include=*.rs", "-w", pattern, str(repo_path)],
            capture_output=True, text=True, timeout=15,
        )
        for line in proc.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            abs_path, line_str, text = parts
            if not line_str.isdigit():
                continue
            line_num = int(line_str)
            rel_path = abs_path.replace(str(repo_path) + "/", "").replace(str(repo_path), "")
            if not rel_path:
                continue
            zone = classify_code_location(rel_path, zone_map)
            if zone.value == target_zone:
                func = _extract_enclosing_function(repo_path, rel_path, line_num)
                results.append((rel_path, line_num, func or rel_path))
                if len(results) >= max_results:
                    return results
    except Exception:
        pass
    return results


def _ensure_boundary_completeness(
    finding: Finding,
    zone_map: ZoneMap,
    caller_graph: dict[str, list],
    repo_path: Path,
) -> Finding:
    """Ensure every TEE-relevant finding has code evidence from both HOST and ENCLAVE sides.

    If a finding only has code_locations on one side of the trust boundary, searches
    for relevant code on the other side and adds it as additional code_locations.
    """
    if not finding.is_tee_relevant or finding.dismissed:
        return finding
    if not finding.code_locations:
        return finding

    # Classify existing code_locations by zone
    has_host = False
    has_enclave = False
    for loc in finding.code_locations:
        zone = classify_code_location(loc.file, zone_map)
        if zone.value == "untrusted":
            has_host = True
        elif zone.value == "trusted":
            has_enclave = True

    if has_host and has_enclave:
        return finding  # Already has both sides

    new_locs: list[CodeLocation] = []

    if has_enclave and not has_host:
        # Missing HOST side — find what host code interacts with this enclave function
        for loc in finding.code_locations:
            zone = classify_code_location(loc.file, zone_map)
            if zone.value != "trusted":
                continue
            func_name = _extract_enclosing_function(repo_path, loc.file, loc.line)
            if not func_name:
                continue

            # Strategy 1: grep for function name in HOST files
            host_refs = _grep_in_zone(func_name, repo_path, zone_map, "untrusted")

            # Strategy 2: search for broader enclave crate references in HOST
            if not host_refs:
                crate_stem = Path(loc.file).parts[1] if len(Path(loc.file).parts) > 1 else None
                if crate_stem:
                    # Search for crate name references in host code
                    host_refs = _grep_in_zone(crate_stem, repo_path, zone_map, "untrusted", max_results=2)

            # Strategy 3: search for pRPC/service method names from the trace
            if not host_refs and finding.trust_boundary_trace:
                for hop in finding.trust_boundary_trace:
                    callee = hop.callee_name
                    if callee and callee not in ("unknown", ""):
                        host_refs = _grep_in_zone(callee, repo_path, zone_map, "untrusted")
                        if host_refs:
                            break

            # Strategy 4: search for key terms from finding title/root_cause
            if not host_refs:
                search_terms = set()
                for term in (finding.title or "").split():
                    term = term.strip("()[]{}.,:;").lower()
                    if len(term) > 4 and term not in ("which", "their", "about", "these", "those", "without"):
                        search_terms.add(term)
                for term in (finding.root_cause or "").split():
                    term = term.strip("()[]{}.,:;").lower()
                    if len(term) > 4 and term not in ("which", "their", "about", "these", "those", "without"):
                        search_terms.add(term)
                for term in search_terms:
                    host_refs = _grep_in_zone(term, repo_path, zone_map, "untrusted", max_results=1)
                    if host_refs:
                        break

            for ref_file, ref_line, ref_func in host_refs[:2]:
                if not (repo_path / ref_file).exists():
                    continue
                snippet = _read_source_snippet(repo_path, ref_file, ref_line)
                if snippet:
                    new_locs.append(CodeLocation(
                        file=ref_file,
                        line=ref_line,
                        snippet=snippet,
                    ))
            break  # Only process first enclave location

    elif has_host and not has_enclave:
        # Missing ENCLAVE side — find what enclave code is affected
        for loc in finding.code_locations:
            zone = classify_code_location(loc.file, zone_map)
            if zone.value != "untrusted":
                continue
            func_name = _extract_enclosing_function(repo_path, loc.file, loc.line)
            if not func_name:
                continue

            # Strategy 1: grep for function name in ENCLAVE files
            enclave_refs = _grep_in_zone(func_name, repo_path, zone_map, "trusted")

            # Strategy 2: search for pRPC method names
            if not enclave_refs:
                # Try common pRPC patterns: function name might be a pRPC method
                enclave_refs = _grep_in_zone(func_name, repo_path, zone_map, "trusted")

            # Strategy 3: search for related enclave operations
            if not enclave_refs:
                # Look for seal/unseal/init/handler patterns in enclave code
                keywords = []
                title_lower = (finding.title or "").lower()
                if "seal" in title_lower or "unseal" in title_lower or "rollback" in title_lower:
                    keywords = ["seal", "unseal"]
                elif "key" in title_lower and ("inject" in title_lower or "dev" in title_lower):
                    keywords = ["init_runtime", "identity"]
                elif "attestation" in title_lower or "quote" in title_lower:
                    keywords = ["attestation", "quote", "report"]
                for kw in keywords:
                    enclave_refs = _grep_in_zone(kw, repo_path, zone_map, "trusted", max_results=1)
                    if enclave_refs:
                        break

            # Strategy 4: use the trust_boundary_trace to find enclave references
            if not enclave_refs and not new_locs and finding.trust_boundary_trace:
                for hop in finding.trust_boundary_trace:
                    if hop.file and (repo_path / hop.file).exists() and classify_code_location(hop.file, zone_map).value == "trusted":
                        snippet = _read_source_snippet(repo_path, hop.file, hop.line)
                        if snippet:
                            new_locs.append(CodeLocation(
                                file=hop.file,
                                line=hop.line,
                                snippet=snippet,
                            ))
                        break

            # Strategy 5: search for key terms from finding title/root_cause in enclave
            if not enclave_refs and not new_locs:
                search_terms = set()
                for term in (finding.title or "").split():
                    term = term.strip("()[]{}.,:;").lower()
                    if len(term) > 4 and term not in ("which", "their", "about", "these", "those", "without"):
                        search_terms.add(term)
                for term in (finding.root_cause or "").split():
                    term = term.strip("()[]{}.,:;").lower()
                    if len(term) > 4 and term not in ("which", "their", "about", "these", "those", "without"):
                        search_terms.add(term)
                for term in search_terms:
                    enclave_refs = _grep_in_zone(term, repo_path, zone_map, "trusted", max_results=1)
                    if enclave_refs:
                        break

            for ref_file, ref_line, ref_func in enclave_refs[:2]:
                if not (repo_path / ref_file).exists():
                    continue
                snippet = _read_source_snippet(repo_path, ref_file, ref_line)
                if snippet:
                    new_locs.append(CodeLocation(
                        file=ref_file,
                        line=ref_line,
                        snippet=snippet,
                    ))
            break  # Only process first host location

    if not new_locs:
        return finding

    # Add new locations to the finding
    updated_locs = list(finding.code_locations) + new_locs
    return finding.model_copy(update={"code_locations": updated_locs})


def _verify_cluster(
    cluster_key: str,
    findings: list[GradedFinding],
    repo_path: Path,
    client: LLMClient,
    temperature: float = 0.0,
    fingerprint_map: str = "",
    taxonomy_focus: str | None = None,
    zone_map: ZoneMap | None = None,
    caller_graph: dict[str, list[CallSite]] | None = None,
    entry_points: list[EntryPoint] | None = None,
) -> tuple[list[Finding], list[Unknown]]:
    """Verify a single finding cluster via LLM."""
    # Deterministic file discovery — find related files before LLM analysis
    seed_files = list({
        gf.code_location.split(":")[0]
        for gf in findings
        if ":" in gf.code_location and gf.code_location.split(":")[0]
    })
    related_files = discover_related_files(repo_path, seed_files, max_depth=2, max_files=6)
    related_paths = {str(f.relative_to(repo_path)) for f in related_files}

    # Build zone context for each finding location
    zone_lines: list[str] = []
    if zone_map and zone_map.zones:
        zone_lines.append(f"Zone map has {len(zone_map.zones)} classified files.")
        for gf in findings:
            file_name = gf.code_location.split(":")[0] if ":" in gf.code_location else gf.code_location
            zone = classify_code_location(file_name, zone_map)
            zone_lines.append(f"  {gf.code_location} → [{zone.value}]")
    zone_context = "\n".join(zone_lines) if zone_lines else "Zone classification not available."

    # Trace call chain with zone annotations
    call_chain_text = "Call chain tracing not available."
    traced_chain: InvocationChain | None = None
    if caller_graph and entry_points and zone_map and findings:
        # Trace invocation chain from first finding's location to entry point
        gf = findings[0]
        parts = gf.code_location.split(":")
        sink_file = parts[0] if parts else ""
        sink_line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        # Extract function name from source code at the finding location
        sink_func = _extract_enclosing_function(repo_path, sink_file, sink_line) or Path(sink_file).stem
        traced_chain = trace_invocation_chain(
            sink_file, sink_func, caller_graph, entry_points, zone_map, repo_path,
        )
        if traced_chain and traced_chain.confidence != "no_chain":
            call_chain_text = format_invocation_chain(traced_chain, zone_map)
        elif zone_map and seed_files:
            # Fallback to reference-based tracing
            old_chain = trace_call_chain(repo_path, seed_files, zone_map, max_depth=4, max_files=15)
            call_chain_text = format_call_chain_for_prompt(old_chain)
    elif zone_map and seed_files:
        chain = trace_call_chain(repo_path, seed_files, zone_map, max_depth=4, max_files=15)
        call_chain_text = format_call_chain_for_prompt(chain)

    # Assemble code context for the cluster
    code_contexts: list[str] = []
    for gf in findings:
        parts = gf.code_location.split(":")
        file_name = parts[0] if parts else ""
        line_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        file_path = repo_path / file_name
        context = _read_code_context(file_path, line_num)
        # Annotate code with zone
        if zone_map:
            zone = classify_code_location(file_name, zone_map)
            code_contexts.append(f"### {gf.code_location} [{zone.value}]\n```\n{context}\n```")
        else:
            code_contexts.append(f"### {gf.code_location}\n```\n{context}\n```")

    # Add context from discovered related files (not already in seeds)
    for rel_file in related_files:
        rel_str = str(rel_file.relative_to(repo_path))
        if rel_str not in seed_files:
            context = _read_code_context(rel_file, None)
            if zone_map:
                zone = classify_code_location(rel_str, zone_map)
                code_contexts.append(f"### Related: {rel_str} [{zone.value}]\n```\n{context}\n```")
            else:
                code_contexts.append(f"### Related: {rel_str}\n```\n{context}\n```")

    code_text = "\n\n".join(code_contexts)
    if len(code_text) > 24000:
        code_text = code_text[:24000] + "\n...[truncated]"

    findings_summary_parts = []
    for gf in findings:
        parts = [f"- {gf.sarif_result_id}: {gf.message} (grade: {gf.grade})"]
        if zone_map:
            zone = classify_code_location(
                gf.code_location.split(":")[0] if ":" in gf.code_location else gf.code_location,
                zone_map,
            )
            parts.append(f"  [Zone: {zone.value}]")
        if _is_test_file(gf.code_location):
            parts.append("  [WARNING: TEST/EXAMPLE file — not production attack surface]")
        findings_summary_parts.append("\n".join(parts))
    findings_summary = "\n".join(findings_summary_parts)

    prompt = load_prompt(
        "deep_verify",
        code_context=code_text,
        findings_summary=findings_summary,
        cluster_id=cluster_key,
        fingerprint_map=fingerprint_map,
        zone_context=zone_context,
        call_chain=call_chain_text,
        discovered_files="\n".join(sorted(related_paths)) if related_paths else "None",
        taxonomy_reference=load_taxonomy(),
    )

    system_prompt = (
        "You are a security researcher performing deep verification of static analysis findings "
        "in a TEE-enabled Web3 project. For each finding cluster: verify the attack path is real, "
        "assign severity (Critical/High/Medium/Low/Info), verify confidence, and write a POC. "
        "If a finding cannot be verified, mark it as an unknown. "
        "Keep titles under 60 chars. Attack path steps: single short sentences (max 80 chars). "
        "Remediation: 1-2 sentences. No filler, no repetition."
    )

    if taxonomy_focus:
        system_prompt += (
            f"\n\nFocus specifically on {taxonomy_focus} TEE usage problems. "
            "Provide deeper analysis for this category."
        )

    try:
        response = parse_with_retry(
            client, system_prompt, prompt, FindingsBatchResponse,
            error_save_dir=None, temperature=temperature,
        )
        # Post-process: inject pre-traced invocation chain into findings
        if traced_chain and zone_map:
            response.findings = [
                _inject_chain_into_finding(f, traced_chain, zone_map, caller_graph)
                for f in response.findings
            ]
        # Fallback: for findings without chains, try to find host→enclave callers
        if caller_graph and zone_map:
            response.findings = [
                _inject_host_caller_context(f, caller_graph, zone_map, repo_path)
                for f in response.findings
            ]
        # Correct LLM-filled zone labels using zone_map and recalculate boundaries
        if zone_map:
            response.findings = [
                _correct_trace_zones(f, zone_map)
                for f in response.findings
            ]
        # Ensure every finding has evidence from both sides of the trust boundary
        if zone_map and caller_graph:
            response.findings = [
                _ensure_boundary_completeness(f, zone_map, caller_graph, repo_path)
                for f in response.findings
            ]
        # Fallback: fill empty code_locations from triage data
        response.findings = _backfill_locations(response.findings, findings)
        return response.findings, response.unknowns
    except Exception as e:
        error_str = str(e)
        is_retryable = (
            "429" in error_str
            or "rate" in error_str.lower()
            or "throttl" in error_str.lower()
            or any(code in error_str for code in ["500", "502", "503", "504"])
        )
        if is_retryable:
            raise  # Let caller handle retry with backoff
        logger.error("Cluster %s verification failed: %s", cluster_key, error_str[:200])
        # Convert to unknowns on non-retryable failure
        unknowns = [
            Unknown(
                id=f"U-{i + 1:02d}",
                title="Verification failed",
                what_was_checked=gf.message[:200] if gf.message else cluster_key,
                why_uncertain=f"LLM verification failed: {error_str[:200]}",
                recommended_steps=["Retry verification manually"],
            )
            for i, gf in enumerate(findings)
        ]
        return [], unknowns


def _verify_cluster_with_retry(
    cluster_key: str,
    findings: list[GradedFinding],
    repo_path: Path,
    client: LLMClient,
    temperature: float = 0.0,
    fingerprint_map: str = "",
    taxonomy_focus: str | None = None,
    zone_map: ZoneMap | None = None,
    caller_graph: dict[str, list[CallSite]] | None = None,
    entry_points: list[EntryPoint] | None = None,
) -> tuple[list[Finding], list[Unknown]]:
    """Verify a cluster with retry and exponential backoff for API errors."""
    for attempt in range(_MAX_API_RETRIES):
        try:
            return _verify_cluster(
                cluster_key, findings, repo_path, client, temperature,
                fingerprint_map=fingerprint_map, taxonomy_focus=taxonomy_focus,
                zone_map=zone_map, caller_graph=caller_graph, entry_points=entry_points,
            )
        except Exception as e:
            error_str = str(e)
            is_retryable = (
                "429" in error_str
                or "rate" in error_str.lower()
                or "throttl" in error_str.lower()
                or any(code in error_str for code in ["500", "502", "503", "504"])
            )
            if not is_retryable or attempt >= _MAX_API_RETRIES - 1:
                logger.error("Cluster %s verification failed after %d attempts: %s",
                             cluster_key, attempt + 1, error_str[:200])
                unknowns = [
                    Unknown(
                        id=f"U-{i + 1:02d}",
                        title="Verification failed",
                        what_was_checked=gf.message[:200] if gf.message else cluster_key,
                        why_uncertain=f"LLM verification failed: {error_str[:200]}",
                        recommended_steps=["Retry verification manually"],
                    )
                    for i, gf in enumerate(findings)
                ]
                return [], unknowns

            backoff = _INITIAL_BACKOFF_SECONDS * (2 ** attempt)
            logger.warning("Cluster %s API error (attempt %d/%d), retrying in %ds: %s",
                           cluster_key, attempt + 1, _MAX_API_RETRIES, backoff, error_str[:200])
            time.sleep(backoff)

    # Should not reach here, but safety fallback
    return [], []


# --- Sub-phase 5b.5: Severity assignment (done inline during verification) ---


def run_deep_verify(
    input_data: Stage5bInput,
    client: LLMClient,
    max_concurrent: int = 3,
    temperature: float = 0.5,
    no_escalate: bool = False,
) -> Stage5bOutput:
    """Run Stage 5b: Deep verification of triaged findings.

    Two-pass auto-escalation:
      Pass 1 — Normal verification of all clusters.
      Pass 2 — Re-run clusters with weak/shallow findings using per-taxonomy prompts.
    """
    logger.info(
        "Stage 5b: Deep verifying %d graded findings",
        len(input_data.graded_findings),
    )

    # Build fingerprint trust boundary map
    fingerprint_map = ""
    if input_data.fingerprint:
        fingerprint_map = build_fingerprint_map(input_data.fingerprint.model_dump())
        if fingerprint_map:
            logger.info("Fingerprint trust boundary map loaded (%d chars)", len(fingerprint_map))

    # Build trust zone map for the repository
    zone_map: ZoneMap | None = None
    try:
        zone_map = build_zone_map(input_data.repo_path)
        # Overlay manifest-derived zones if available
        if zone_map and input_data.fingerprint and input_data.fingerprint.manifest_trusted_files:
            zone_map = overlay_manifest_zones(
                zone_map, input_data.fingerprint.manifest_trusted_files,
            )
            logger.info(
                "Zone map enriched with manifest data: %d manifest trusted files",
                len(input_data.fingerprint.manifest_trusted_files),
            )
        if zone_map.zones:
            logger.info(
                "Zone map built: %d files (%d trusted, %d untrusted, %d mixed)",
                len(zone_map.zones),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.TRUSTED),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.UNTRUSTED),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.MIXED),
            )
            # LLM-assisted project role inference for repos with ambiguous zones
            total = len(zone_map.zones)
            mixed_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.MIXED)
            unknown_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.UNKNOWN)
            ambiguous = mixed_count + unknown_count
            sparse = total < 10
            high_ambiguity = ambiguous > total * 0.1
            if sparse or high_ambiguity:
                logger.info(
                    "Running project role inference (%d mixed + %d unknown / %d total, sparse=%s)",
                    mixed_count, unknown_count, total, sparse,
                )
                try:
                    role = infer_project_tee_role(input_data.repo_path, zone_map, client)
                    if role:
                        zone_map = apply_project_role_to_zones(zone_map, role, input_data.repo_path)
                except Exception as e:
                    logger.warning("Project role inference failed: %s", str(e)[:200])
                # Reconcile directory-level inconsistencies
                from tee_audit.utils.call_graph import reconcile_directory_zones
                zone_map = reconcile_directory_zones(zone_map)
            # Enhance fingerprint map with zone info
            fingerprint_map = build_fingerprint_map(
                input_data.fingerprint.model_dump() if input_data.fingerprint else None,
                zone_map=zone_map,
            )
    except Exception as e:
        logger.warning("Zone map construction failed: %s", str(e)[:200])

    # Build caller graph and discover entry points for invocation chain tracing
    caller_graph: dict[str, list[CallSite]] | None = None
    entry_points: list[EntryPoint] | None = None
    if zone_map:
        try:
            caller_graph = build_caller_graph(input_data.repo_path, zone_map)
            entry_points = discover_entry_points(input_data.repo_path, zone_map)
            logger.info(
                "Invocation chain infrastructure: %d callee keys, %d entry points",
                len(caller_graph), len(entry_points),
            )
        except Exception as e:
            logger.warning("Caller graph construction failed: %s", str(e)[:200])

    # Sub-phase 5b.1: Cluster
    clusters = _cluster_by_invariant_and_file(input_data.graded_findings)
    logger.info("Clustered into %d groups", len(clusters))

    # Sub-phase 5b.3: Pass 1 — Parallel verification with retry
    all_findings: list[Finding] = []
    all_unknowns: list[Unknown] = []
    cluster_results: dict[str, tuple[list[Finding], list[Unknown]]] = {}

    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = {
            executor.submit(
                _verify_cluster_with_retry, key, cluster, input_data.repo_path,
                client, temperature, fingerprint_map, None, zone_map,
                caller_graph, entry_points,
            ): key
            for key, cluster in clusters.items()
        }

        for future in as_completed(futures):
            key = futures[future]
            try:
                findings, unknowns = future.result()
                cluster_results[key] = (findings, unknowns)
                all_findings.extend(findings)
                all_unknowns.extend(unknowns)
            except Exception as e:
                logger.error("Cluster %s failed: %s", key, str(e)[:200])

    # Sub-phase 5b.4: Pass 2 — Auto-escalation for weak clusters
    if not no_escalate:
        weak_clusters = _identify_weak_clusters(cluster_results)
        if weak_clusters:
            logger.info(
                "Auto-escalation: re-running %d weak clusters with per-taxonomy prompts",
                len(weak_clusters),
            )
            _rerun_weak_clusters(
                weak_clusters, clusters, input_data.repo_path, client,
                temperature, fingerprint_map, max_concurrent,
                all_findings, all_unknowns, zone_map,
                caller_graph, entry_points,
            )

    # Assign sequential IDs and populate code snippets (skip locations with no valid file)
    enriched_findings: list[Finding] = []
    for i, f in enumerate(all_findings):
        new_locs: list[CodeLocation] = []
        for loc in f.code_locations:
            snippet = loc.snippet
            if not snippet and loc.file:
                # Try exact path first, then fuzzy resolve
                file_path = input_data.repo_path / loc.file
                if file_path.exists():
                    snippet = _read_code_context(file_path, loc.line, context_lines=20)
                else:
                    # Fuzzy resolve: try matching filename
                    filename = loc.file.split("/")[-1]
                    for match in input_data.repo_path.rglob(filename):
                        if match.is_file():
                            snippet = _read_code_context(match, loc.line, context_lines=20)
                            break
            # Only keep locations with valid source or existing files
            if snippet or (loc.file and (input_data.repo_path / loc.file).exists()):
                new_locs.append(loc.model_copy(update={"snippet": snippet}))
        enriched_findings.append(f.model_copy(update={
            "id": f"V-{i + 1:02d}",
            "code_locations": new_locs,
        }))
    all_findings = enriched_findings
    all_unknowns = [
        u.model_copy(update={"id": f"U-{i + 1:02d}"})
        for i, u in enumerate(all_unknowns)
    ]

    logger.info(
        "Stage 5b complete: %d verified findings, %d unknowns",
        len(all_findings),
        len(all_unknowns),
    )

    # Persist zone_map for stage 6 (report rendering)
    if zone_map:
        try:
            zone_map_path = input_data.repo_path.parent / "artifact" / "zone_map.json"
            zone_map_path.parent.mkdir(parents=True, exist_ok=True)
            zone_map_path.write_text(zone_map.model_dump_json(indent=2))
            logger.info("Zone map persisted to %s", zone_map_path)
        except Exception as e:
            logger.warning("Failed to persist zone_map: %s", str(e)[:200])

    return Stage5bOutput(verified_findings=all_findings, unknowns=all_unknowns)


# --- Auto-escalation helpers ---

_TAXONOMY_FOCUS_MAP = {
    "Flow": "Trust Boundary Flow — secrets/data crossing TEE boundaries incorrectly",
    "Guard": "Verification Gap — missing or incomplete TEE verification",
    "Binding": "Binding Weakness — incomplete cryptographic/identity binding",
    "State": "State Continuity — sealed state, checkpoint, or epoch issues",
    "Config": "Configuration Integrity — build flags, debug modes weakening TEE",
    "Design": "Design Appropriateness — TEE used in wrong places or incomplete trust paths",
    "Leakage": "Output & Metadata Leakage — response length, error detail, or metadata revealing enclave state",
}


def _identify_weak_clusters(
    cluster_results: dict[str, tuple[list[Finding], list[Unknown]]],
) -> list[str]:
    """Identify clusters that produced only weak/unknown results.

    A cluster is weak if:
    - All findings are Info severity or dismissed, OR
    - More unknowns than findings were produced.
    """
    weak: list[str] = []
    for key, (findings, unknowns) in cluster_results.items():
        if not findings and not unknowns:
            continue
        active = [f for f in findings if not f.dismissed]
        if not active and unknowns:
            weak.append(key)
        elif len(unknowns) > len(active):
            weak.append(key)
        elif active and all(f.severity == Severity.INFO for f in active):
            weak.append(key)
    return weak


def _infer_taxonomy_focus(cluster_key: str) -> str | None:
    """Try to infer a taxonomy focus from the cluster key (invariant_id::file)."""
    family = cluster_key.split("::")[0] if "::" in cluster_key else ""
    # Invariant IDs are like INV-NN, not family names — return None for generic
    return None


def _rerun_weak_clusters(
    weak_keys: list[str],
    clusters: dict[str, list[GradedFinding]],
    repo_path: Path,
    client: LLMClient,
    temperature: float,
    fingerprint_map: str,
    max_concurrent: int,
    all_findings: list[Finding],
    all_unknowns: list[Unknown],
    zone_map: ZoneMap | None = None,
    caller_graph: dict[str, list[CallSite]] | None = None,
    entry_points: list[EntryPoint] | None = None,
) -> None:
    """Re-verify weak clusters with taxonomy-specific prompts. Mutates all_findings/all_unknowns."""
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = {}
        for key in weak_keys:
            if key not in clusters:
                continue
            taxonomy_focus = "TEE usage problem"
            futures[executor.submit(
                _verify_cluster_with_retry, key, clusters[key], repo_path,
                client, temperature, fingerprint_map, taxonomy_focus, zone_map,
                caller_graph, entry_points,
            )] = key

        for future in as_completed(futures):
            key = futures[future]
            try:
                findings, unknowns = future.result()
                all_findings.extend(findings)
                all_unknowns.extend(unknowns)
                logger.info("Escalated cluster %s: %d findings, %d unknowns", key, len(findings), len(unknowns))
            except Exception as e:
                logger.error("Escalated cluster %s failed: %s", key, str(e)[:200])


def postprocess_boundary_completeness(
    findings: list[Finding],
    repo_path: Path,
    fingerprint=None,
    llm_client=None,
) -> list[Finding]:
    """Apply zone correction and boundary completeness to findings from any path.

    Works for both SARIF-based and LLM-fallback findings. Builds zone_map and
    caller_graph from the repo, then applies _correct_trace_zones and
    _ensure_boundary_completeness to every TEE-relevant finding.

    When llm_client is provided and the heuristic zone map has many MIXED/UNKNOWN
    zones, uses LLM to infer the project's TEE role and reclassify zones.
    """
    if not findings:
        return findings

    zone_map: ZoneMap | None = None
    try:
        zone_map = build_zone_map(repo_path)
        if zone_map and fingerprint and fingerprint.manifest_trusted_files:
            zone_map = overlay_manifest_zones(zone_map, fingerprint.manifest_trusted_files)

        # LLM-assisted project role inference for repos with ambiguous zones
        if zone_map and zone_map.zones and llm_client:
            total = len(zone_map.zones)
            mixed_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.MIXED)
            unknown_count = sum(1 for z in zone_map.zones.values() if z == TrustZone.UNKNOWN)
            ambiguous = mixed_count + unknown_count
            sparse = total < 10
            high_ambiguity = ambiguous > total * 0.1
            if sparse or high_ambiguity:
                logger.info(
                    "Running project role inference (%d mixed + %d unknown / %d total, sparse=%s)",
                    mixed_count, unknown_count, total, sparse,
                )
                try:
                    role = infer_project_tee_role(repo_path, zone_map, llm_client)
                    if role:
                        zone_map = apply_project_role_to_zones(zone_map, role, repo_path)
                except Exception as e:
                    logger.warning("Project role inference failed: %s", str(e)[:200])

        if zone_map and zone_map.zones:
            logger.info(
                "Boundary post-processing: zone map with %d files (%d trusted, %d untrusted, %d mixed)",
                len(zone_map.zones),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.TRUSTED),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.UNTRUSTED),
                sum(1 for z in zone_map.zones.values() if z == TrustZone.MIXED),
            )
    except Exception as e:
        logger.warning("Boundary post-processing: zone map failed: %s", str(e)[:200])
        return findings

    # Persist zone_map for the report stage
    try:
        zone_map_path = repo_path.parent / "artifact" / "zone_map.json"
        zone_map_path.parent.mkdir(parents=True, exist_ok=True)
        zone_map_path.write_text(zone_map.model_dump_json(indent=2))
        logger.info("Zone map persisted to %s", zone_map_path)
    except Exception as e:
        logger.warning("Failed to persist zone map: %s", str(e)[:200])

    caller_graph: dict[str, list[CallSite]] | None = None
    try:
        caller_graph = build_caller_graph(repo_path, zone_map)
    except Exception as e:
        logger.warning("Boundary post-processing: caller graph failed: %s", str(e)[:200])

    # Correct LLM-filled zone labels
    findings = [_correct_trace_zones(f, zone_map) for f in findings]

    # Ensure every finding has evidence from both sides of the trust boundary
    if caller_graph:
        before = sum(
            1 for f in findings
            if f.is_tee_relevant and not f.dismissed and f.code_locations
            and len({classify_code_location(loc.file, zone_map).value for loc in f.code_locations}) >= 2
        )
        findings = [
            _ensure_boundary_completeness(f, zone_map, caller_graph, repo_path)
            for f in findings
        ]
        after = sum(
            1 for f in findings
            if f.is_tee_relevant and not f.dismissed and f.code_locations
            and len({classify_code_location(loc.file, zone_map).value for loc in f.code_locations}) >= 2
        )
        logger.info("Boundary completeness: %d → %d findings with multi-zone evidence", before, after)

    return findings
