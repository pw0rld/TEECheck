from __future__ import annotations

"""Stage 7: Report Review & Refinement — ralph loop for report quality.

Iteratively reviews the stage 6 report, generates findings from invariants
when CodeQL produced nothing, and refines until quality threshold is met.
"""


def _coerce_evidence(val) -> str:
    """Coerce code_evidence from list or other types to string."""
    if isinstance(val, list):
        return "; ".join(str(v) for v in val)
    if isinstance(val, str):
        return val
    return str(val) if val is not None else ""

import json
import logging
import re
from pathlib import Path

from pydantic import BaseModel

from tee_audit.contracts import Stage6Output, Stage7Output
from tee_audit.llm.client import LLMClient
from tee_audit.llm.prompt_loader import load_prompt, load_taxonomy
from tee_audit.llm.response_parser import parse_with_retry
from tee_audit.models.finding import (
    CodeLocation,
    Confidence,
    Finding,
    Severity,
    TrustPathTier,
)
from tee_audit.models.invariant import family_to_taxonomy
from tee_audit.models.triage import PositiveGuard
from tee_audit.models.report import Report
from tee_audit.models.unknown import Unknown
from tee_audit.stages.report import (
    _build_dashboard,
    _render_markdown_report,
    ReportResponse,
)

logger = logging.getLogger(__name__)

MAX_RALPH_ITERATIONS = 3
QUALITY_THRESHOLD = 0.85


def _validate_code_locs(locs_data: list, repo_path: Path) -> list[CodeLocation]:
    """Validate LLM-generated code locations against the actual repo.

    Only keeps locations where the file exists on disk. Reads a source snippet
    for each valid location so the report renderer always has real source code.
    """
    valid: list[CodeLocation] = []
    for loc in locs_data:
        if not isinstance(loc, dict):
            continue
        file_rel = loc.get("file", "")
        if not file_rel or file_rel == "unknown":
            continue
        line_num = loc.get("line")

        # Exact match
        target = repo_path / file_rel
        resolved = file_rel
        if not target.exists():
            # Fuzzy match by filename
            filename = file_rel.split("/")[-1]
            for match in repo_path.rglob(filename):
                if match.is_file():
                    target = match
                    resolved = str(match.relative_to(repo_path))
                    break
            else:
                continue  # File not found, skip this location

        # Read source snippet
        try:
            all_lines = target.read_text(errors="replace").splitlines()
        except OSError:
            continue

        if not all_lines:
            continue

        center = (line_num or len(all_lines)) - 1
        center = min(max(center, 0), len(all_lines) - 1)
        context_lines = 10
        start = max(0, center - context_lines)
        end = min(len(all_lines), center + context_lines + 1)
        snippet_parts = []
        for i in range(start, end):
            marker = ">>>" if i == center else "   "
            snippet_parts.append(f"{marker} {i + 1:4d} | {all_lines[i]}")
        snippet = "\n".join(snippet_parts)

        valid.append(CodeLocation(
            file=resolved,
            line=line_num,
            snippet=snippet,
        ))
    return valid


class ReviewResponse(BaseModel):
    quality_score: float = 0.0
    critique: str = ""
    improvement_suggestions: list[str] = []
    needs_refinement: bool = True
    false_positive_ids: list[str] = []
    severity_adjustments: list[dict] = []
    adversarial_notes: str = ""
    dismissal_reasons: dict[str, str] = {}


class InvariantVerifyResponse(BaseModel):
    has_finding: bool = False
    finding: dict | None = None
    positive_guard: dict | None = None
    unknown: dict | None = None


class ResolvedUnknownResponse(BaseModel):
    resolved: bool = False
    finding: dict | None = None
    positive_guard: dict | None = None
    resolution_notes: str = ""


def _extract_relevant_blocks(
    file_path: Path, repo_path: Path, keywords: list[str], max_blocks: int = 4,
) -> str:
    """Extract only functions/blocks containing keywords from a source file.

    Instead of dumping the entire file, find the relevant code blocks and
    extract each with a small context window.
    """
    try:
        lines = file_path.read_text(errors="ignore").splitlines()
    except OSError:
        return ""

    rel = file_path.relative_to(repo_path)
    kw_lower = [k.lower() for k in keywords]
    total = len(lines)
    extracted_blocks: list[str] = []
    used_ranges: list[tuple[int, int]] = []

    for i, line in enumerate(lines):
        if len(extracted_blocks) >= max_blocks:
            break
        line_lower = line.lower()
        if not any(kw in line_lower for kw in kw_lower):
            continue

        # Find block boundaries: look for function/struct/enum/impl declarations
        block_start = i
        for j in range(i, max(0, i - 30), -1):
            stripped = lines[j].strip()
            if re.match(r'^(pub\s+)?(fn|struct|enum|impl|trait|mod|type)\b', stripped):
                block_start = j
                break
            if re.match(r'^(func|type|var|const|interface|package)\b', stripped):
                block_start = j
                break

        # Find block end: next declaration or closing brace at same indent level
        block_end = min(total, i + 40)
        for j in range(block_start + 1, min(total, block_start + 100)):
            stripped = lines[j].strip()
            # Next top-level declaration
            if j > block_start + 3 and re.match(
                r'^(pub\s+)?(fn|struct|enum|impl|trait|mod|type)\b', stripped
            ):
                block_end = j
                break
            if re.match(r'^(func|type|var|const|interface|package)\b', stripped):
                block_end = j
                break

        # Check overlap with already-extracted ranges
        if any(block_start <= r_end and block_end >= r_start for r_start, r_end in used_ranges):
            continue

        used_ranges.append((block_start, block_end))
        block_lines = lines[block_start:block_end]
        snippet = "\n".join(
            f"{block_start + k + 1:4d} | {block_lines[k]}"
            for k in range(len(block_lines))
        )
        extracted_blocks.append(snippet)

    if not extracted_blocks:
        return ""

    header = f"### {rel}"
    return header + "\n```\n" + "\n    ...\n".join(extracted_blocks) + "\n```"


def _get_invariant_keywords(invariant) -> list[str]:
    """Extract search keywords from an invariant's sources, sinks, and guards."""
    keywords: list[str] = []
    for ref in list(invariant.sources) + list(invariant.sinks):
        # Extract meaningful tokens from references
        for token in re.split(r'[/.:()>[\]\s]+', ref):
            if len(token) > 2 and token.lower() not in ("the", "and", "for", "from"):
                keywords.append(token)
    if hasattr(invariant, "guards") and invariant.guards:
        keywords.extend(invariant.guards[:5])
    if hasattr(invariant, "failure_modes") and invariant.failure_modes:
        for fm in invariant.failure_modes[:3]:
            keywords.extend(re.findall(r'\b\w{4,}\b', fm.lower()))
    return keywords


def _discover_source_dirs(repo_path: Path) -> list[Path]:
    """Dynamically discover all directories containing source files.

    Searches for Rust/Go/Python/TS/Solidity files and returns unique parent
    directories, not limited to hardcoded names like 'src' or 'core'.
    """
    _SKIP_DIRS = {
        "target", "build", "dist", "node_modules", ".git", "cargo-home",
        "codeql-dbs", "tee-audit-output", "cargo-target", "vendor",
    }
    _SOURCE_EXTS = {".rs", ".go", ".py", ".ts", ".js", ".sol", ".c", ".h"}

    seen: set[Path] = set()
    result: list[Path] = []

    for ext in _SOURCE_EXTS:
        for f in repo_path.rglob(f"*{ext}"):
            parts = f.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            str_path = str(f)
            if "registry/src" in str_path or ".cargo" in str_path:
                continue
            parent = f.parent
            if parent not in seen:
                seen.add(parent)
                result.append(parent)

    return result


def _search_all_source_dirs(
    repo_path: Path, keywords: list[str], seen_files: set[Path],
    max_files: int = 30,
) -> list[tuple[int, Path]]:
    """Search across ALL discovered source directories for keyword matches."""
    _SKIP_DIRS = {
        "target", "build", "dist", "node_modules", ".git", "cargo-home",
        "codeql-dbs", "tee-audit-output", "cargo-target", "vendor",
    }
    _SOURCE_EXTS = {".rs", ".go", ".py", ".ts", ".sol"}

    scored: list[tuple[int, Path]] = []
    scanned = 0
    kw_lower = [k.lower() for k in keywords]

    for ext in _SOURCE_EXTS:
        for f in repo_path.rglob(f"*{ext}"):
            if scanned >= max_files or f in seen_files:
                continue
            parts = f.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            str_path = str(f)
            if "registry/src" in str_path or ".cargo" in str_path:
                continue
            scanned += 1
            try:
                content_lower = f.read_text(errors="ignore").lower()
                score = sum(1 for kw in kw_lower if kw in content_lower)
                if score >= 2:
                    scored.append((score, f))
            except OSError:
                continue

    scored.sort(key=lambda x: -x[0])
    return scored


def _search_docs_and_configs(
    repo_path: Path, keywords: list[str], max_files: int = 8,
) -> list[str]:
    """Search documentation and config files for security-relevant context.

    Reads README, Cargo.toml, Dockerfiles, CLAUDE.md, audit docs, etc.
    """
    _DOC_PATTERNS = [
        "README*", "CLAUDE.md", "SECURITY*", "AUDIT*",
        "Cargo.toml", "Dockerfile*", "*.dockerfile",
        "docker-compose*", "*.edl", "*.json",
    ]
    _SKIP_DIRS = {
        "target", "build", "dist", "node_modules", ".git", "cargo-home",
        "codeql-dbs", "tee-audit-output", "cargo-target", "vendor",
    }
    kw_lower = [k.lower() for k in keywords]
    results: list[str] = []
    seen: set[Path] = set()

    for pattern in _DOC_PATTERNS:
        for f in repo_path.rglob(pattern):
            if len(results) >= max_files or f in seen:
                break
            parts = f.relative_to(repo_path).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            str_path = str(f)
            if "registry/src" in str_path or ".cargo" in str_path:
                continue
            if not f.is_file() or f.stat().st_size > 500_000:
                continue
            seen.add(f)
            try:
                content = f.read_text(errors="ignore")
                content_lower = content.lower()
                relevance = sum(1 for kw in kw_lower if kw in content_lower)
                if relevance > 0:
                    rel_path = f.relative_to(repo_path)
                    # Truncate large files
                    truncated = content[:3000] if len(content) > 3000 else content
                    results.append(f"### {rel_path} (relevance: {relevance})\n```\n{truncated}\n```")
            except OSError:
                continue

    return results


def _read_invariant_code(
    repo_path: Path, invariant, context_lines: int = 250,
) -> str:
    """Read source code + docs relevant to an invariant — multi-strategy search."""
    all_refs = list(invariant.sources) + list(invariant.sinks)
    code_parts: list[str] = []
    seen_files: set[Path] = set()

    _SKIP_DIRS = {
        "target", "build", "dist", "node_modules", ".git", "cargo-home",
        "codeql-dbs", "tee-audit-output", "cargo-target", "vendor",
    }

    def _is_relevant_file(p: Path) -> bool:
        parts = p.relative_to(repo_path).parts
        if any(part in _SKIP_DIRS for part in parts):
            return False
        str_path = str(p)
        if "cargo-home" in str_path or "registry/src" in str_path or ".cargo" in str_path:
            return False
        return True

    keywords = _get_invariant_keywords(invariant)

    # Strategy 1: Resolve source/sink references to files, extract relevant blocks
    for ref in all_refs:
        candidates = _resolve_code_ref(repo_path, ref)
        relevant = [p for p in candidates if _is_relevant_file(p)]
        for path in relevant[:2]:
            if path in seen_files:
                continue
            seen_files.add(path)
            block = _extract_relevant_blocks(path, repo_path, keywords)
            if block:
                code_parts.append(block)
            else:
                try:
                    lines = path.read_text(errors="ignore").splitlines()
                    snippet = "\n".join(
                        f"{i + 1:4d} | {lines[i]}" for i in range(min(len(lines), 80))
                    )
                    code_parts.append(f"### {path.relative_to(repo_path)}\n```\n{snippet}\n```")
                except OSError:
                    continue

    # Strategy 2: Search ALL source dirs by keyword density (not just hardcoded dirs)
    if not code_parts:
        scored = _search_all_source_dirs(repo_path, keywords, seen_files, max_files=30)
        for _, match in scored[:5]:
            if match in seen_files:
                continue
            seen_files.add(match)
            block = _extract_relevant_blocks(match, repo_path, keywords)
            if block:
                code_parts.append(block)
            else:
                try:
                    lines = match.read_text(errors="ignore").splitlines()
                    snippet = "\n".join(
                        f"{i + 1:4d} | {lines[i]}" for i in range(min(len(lines), 80))
                    )
                    code_parts.append(f"### {match.relative_to(repo_path)}\n```\n{snippet}\n```")
                except OSError:
                    continue

    # Strategy 3: grep for guard keywords across all source files
    if not code_parts:
        guard_kw = invariant.guards[:3] if hasattr(invariant, "guards") else []
        if guard_kw:
            scored = _search_all_source_dirs(repo_path, guard_kw, seen_files, max_files=30)
            for _, match in scored[:3]:
                if match in seen_files:
                    continue
                seen_files.add(match)
                block = _extract_relevant_blocks(match, repo_path, keywords)
                if block:
                    code_parts.append(block)

    # Strategy 4: Search docs and config files for additional context
    doc_results = _search_docs_and_configs(repo_path, keywords, max_files=5)
    if doc_results:
        code_parts.append("## Documentation & Config Context\n" + "\n\n".join(doc_results))

    result = "\n\n".join(code_parts)
    if len(result) > 14000:
        result = result[:14000] + "\n...[truncated]"
    return result or "[No relevant source code found]"


def _resolve_code_ref(repo_path: Path, ref: str) -> list[Path]:
    """Try to resolve a source/sink reference to actual file paths."""
    # Clean up the reference
    clean = re.sub(r"[()]", "", ref).strip()
    candidates: list[Path] = []

    # Direct file match
    direct = repo_path / clean
    if direct.exists():
        candidates.append(direct)

    # Try as filename component
    for part in clean.split("/"):
        for match in repo_path.rglob(part):
            if match.is_file() and match.suffix in (".rs", ".go", ".py", ".ts", ".js", ".c", ".h"):
                candidates.append(match)

    # Try grepping for the reference as a function/type name
    if not candidates:
        base_name = clean.split(".")[-1].split("::")[-1].split("->")[-1].strip()
        if base_name and len(base_name) > 2:
            for ext in ("*.rs", "*.go", "*.py", "*.ts"):
                for match in repo_path.rglob(ext):
                    try:
                        if base_name in match.read_text(errors="ignore"):
                            candidates.append(match)
                            if len(candidates) >= 2:
                                return candidates
                    except OSError:
                        continue

    return candidates


def _verify_single_invariant(
    invariant,
    repo_path: Path,
    client: LLMClient,
    temperature: float = 0.3,
) -> tuple[list[Finding], list[PositiveGuard], list[Unknown]]:
    """Verify one invariant against the codebase via LLM."""
    code_context = _read_invariant_code(repo_path, invariant)

    guards_str = ", ".join(invariant.guards) if hasattr(invariant, "guards") and invariant.guards else "N/A"
    failure_str = ", ".join(invariant.failure_modes) if hasattr(invariant, "failure_modes") and invariant.failure_modes else "N/A"

    prompt = load_prompt(
        "invariant_verify",
        invariant_id=invariant.id,
        invariant_description=invariant.description,
        invariant_trust_path=invariant.trust_path,
        invariant_family=invariant.family.value if hasattr(invariant.family, "value") else str(invariant.family),
        invariant_guards=guards_str,
        invariant_failure_modes=failure_str,
        code_context=code_context,
    )

    system_prompt = (
        "You are a security researcher verifying TEE security invariants against source code. "
        "Be thorough and specific. Reference exact file paths and line numbers. "
        "Only report findings you can back with code evidence. "
        "Keep titles under 60 chars. Attack path steps must be single short sentences (max 80 chars). "
        "Remediation: 1-2 sentences max. No filler, no repetition."
    )

    try:
        response = parse_with_retry(
            client, system_prompt, prompt, InvariantVerifyResponse,
            error_save_dir=None, temperature=temperature,
        )
    except Exception as e:
        logger.warning("Invariant %s verification failed: %s", invariant.id, str(e)[:200])
        return [], [], [Unknown(
            id=f"U-{invariant.id}",
            title=f"Invariant {invariant.id} unresolved",
            what_was_checked=invariant.description[:200],
            why_uncertain=f"LLM verification failed: {str(e)[:200]}",
            recommended_steps=["Retry verification manually"],
        )]

    findings: list[Finding] = []
    positive_guards: list[PositiveGuard] = []
    unknowns: list[Unknown] = []

    if response.has_finding and response.finding:
        f = response.finding
        severity = _parse_enum(Severity, f.get("severity", "Medium"), Severity.MEDIUM)
        confidence = _parse_enum(Confidence, f.get("confidence", "Likely"), Confidence.LIKELY)

        code_locs = _validate_code_locs(f.get("code_locations", []), repo_path)

        findings.append(Finding(
            id=f"IV-{invariant.id}",
            invariant_id=invariant.id,
            severity=severity,
            confidence=confidence,
            title=f.get("title", f"Invariant {invariant.id} violation"),
            attack_path=f.get("attack_path", []),
            code_locations=code_locs,
            remediation=f.get("remediation", ""),
            trust_path_tier=TrustPathTier.CORE,
            cwe_id=f.get("cwe_id"),
            impact=f.get("impact", ""),
            root_cause=f.get("root_cause", ""),
            preconditions=f.get("preconditions", []),
            tee_category=family_to_taxonomy(invariant.family) if invariant else None,
            tee_dimension=invariant.tee_dimension if invariant else None,
            is_tee_relevant=True,
        ))
    elif response.positive_guard:
        pg = response.positive_guard
        positive_guards.append(PositiveGuard(
            id=f"PG-{invariant.id}",
            invariant_refs=[invariant.id],
            trust_path_tier=TrustPathTier.CORE,
            title=pg.get("title", ""),
            description=pg.get("description", f"Guard for {invariant.id} confirmed"),
            code_evidence=_coerce_evidence(pg.get("code_evidence", "")),
            completeness_status=pg.get("completeness", "partial"),
        ))
    elif response.unknown:
        u = response.unknown
        unknowns.append(Unknown(
            id=f"U-{invariant.id}",
            title=u.get("title", "")[:60],
            what_was_checked=u.get("what_was_checked", invariant.description[:200]),
            why_uncertain=u.get("why_uncertain", "Could not determine with available code context"),
            recommended_steps=u.get("recommended_steps", []),
        ))

    return findings, positive_guards, unknowns


def _parse_enum(enum_cls, value, default):
    """Parse an enum value safely."""
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except (ValueError, KeyError):
        pass
    # Try case-insensitive
    for member in enum_cls:
        if member.value.lower() == str(value).lower():
            return member
    return default


def _review_report(
    client: LLMClient,
    report,
    temperature: float = 0.0,
) -> ReviewResponse:
    """Review report quality via LLM."""
    findings_summary = json.dumps(
        [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "has_attack_path": len(f.attack_path) > 0,
                "has_code_locations": len(f.code_locations) > 0,
            }
            for f in report.findings
        ],
        indent=2,
    )

    prompt = load_prompt(
        "report_review",
        project_name=report.project_name,
        findings_count=str(len(report.findings)),
        guards_count=str(len(report.positive_guards)),
        unknowns_count=str(len(report.unknowns)),
        invariants_count=str(len(report.invariants)),
        executive_summary=report.executive_summary[:2000],
        findings_summary=findings_summary[:3000],
        taxonomy_reference=load_taxonomy(),
    )

    try:
        return parse_with_retry(
            client,
            "You are a senior security auditor evaluating the quality of a TEE audit report.",
            prompt,
            ReviewResponse,
            error_save_dir=None,
            temperature=temperature,
        )
    except Exception as e:
        logger.warning("Report review failed: %s", str(e)[:200])
        return ReviewResponse(
            quality_score=0.3,
            critique=f"Review LLM call failed: {str(e)[:200]}",
            improvement_suggestions=["Re-run report generation"],
            needs_refinement=True,
        )


def _refine_executive_summary(
    client: LLMClient,
    report,
    review: ReviewResponse,
    temperature: float = 0.0,
) -> str:
    """Re-generate executive summary incorporating review feedback."""
    findings_summary = json.dumps(
        [{"id": f.id, "title": f.title, "severity": f.severity.value}
         for f in report.findings if not f.dismissed],
        indent=2,
    )
    guards_summary = json.dumps(
        [{"id": pg.id, "title": pg.title, "invariant_refs": pg.invariant_refs,
          "completeness": pg.completeness_status}
         for pg in report.positive_guards],
        indent=2,
    )
    unknowns_summary = json.dumps(
        [{"id": u.id, "what_was_checked": u.what_was_checked[:120]}
         for u in report.unknowns],
        indent=2,
    )

    user_prompt = (
        f"The previous executive summary was deemed low quality.\n\n"
        f"**Reviewer critique**: {review.critique}\n\n"
        f"**Suggestions**: {'; '.join(review.improvement_suggestions)}\n\n"
        f"**Active Findings**:\n{findings_summary}\n\n"
        f"**Positive Guards** ({len(report.positive_guards)} confirmed):\n{guards_summary}\n\n"
        f"**Unknowns** ({len(report.unknowns)} items):\n{unknowns_summary}\n\n"
        f"**Dismissed findings**: {len([f for f in report.findings if f.dismissed])} "
        f"(false positives removed during adversarial review)\n\n"
        f"Write a better executive summary that is specific, factual, and references actual findings and guards."
    )

    try:
        response = parse_with_retry(
            client,
            "You are a security auditor writing an executive summary for a TEE audit report. "
            "Be specific: reference finding counts by severity, name key vulnerabilities, "
            "and give actionable recommendations. "
            "2-3 short paragraphs max. Use bullet lists. No filler, no repetition, no hedging.",
            user_prompt,
            ReportResponse,
            error_save_dir=None,
            temperature=temperature,
        )
        return response.executive_summary
    except Exception as e:
        logger.warning("Summary refinement failed: %s", str(e)[:200])
        return report.executive_summary


def _challenge_findings(
    findings: list[Finding],
    client: LLMClient,
    temperature: float = 0.0,
) -> tuple[list[Finding], list[str]]:
    """Adversarial review: challenge each finding for false positives.

    Enhanced with zone-aware and chain-evidence checks.
    Returns (updated_findings, challenge_log).
    """
    if not findings:
        return findings, []

    findings_detail = json.dumps(
        [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "code_locations": [{"file": loc.file, "line": loc.line} for loc in f.code_locations],
                "attack_path": f.attack_path[:5],
                "invariant_id": f.invariant_id,
                "is_tee_relevant": f.is_tee_relevant,
                "tee_category": f.tee_category.value if f.tee_category else None,
                "has_trust_boundary_trace": bool(f.trust_boundary_trace),
                "trust_boundary_prose_length": len(f.trust_boundary_prose) if f.trust_boundary_prose else 0,
            }
            for f in findings
        ],
        indent=2,
    )

    challenge_prompt = (
        "You are a skeptical security reviewer performing ADVERSARIAL review of these findings.\n\n"
        f"## Findings to Challenge\n\n{findings_detail}\n\n"
        "## Your Task\n\n"
        "For EACH finding, decide:\n"
        "1. Is it in TEST CODE only? (file paths containing test/, tests/, examples/, benches/, bin/)\n"
        "2. Is the severity APPROPRIATE? (e.g., debug output in a test binary is not Low, it is Info)\n"
        "3. Is it a REAL vulnerability or a misunderstood TEE pattern?\n"
        "   - report_data in SGX quotes is an OUTPUT field, not an input to validate\n"
        "   - A verifier returning parsed fields for the caller to check is correct API design\n"
        "   - CLI/test output is not production attack surface\n"
        "4. Can the attack path actually be exploited end-to-end?\n"
        "5. Does the finding have concrete end-to-end chain evidence? If `has_trust_boundary_trace` is false\n"
        "   AND the attack_path is vague or describes imagined scenarios rather than concrete code flow,\n"
        "   it is likely a false positive.\n"
        "6. For TEE-relevant findings (`is_tee_relevant: true`): does the attack involve untrusted input\n"
        "   crossing into trusted code, or trusted output leaking to untrusted code? If the finding\n"
        "   describes a problem entirely within the enclave that would require breaking the TEE itself,\n"
        "   dismiss it — that's out of scope.\n"
        "7. Is the finding based on a SINGLE function examined in isolation, without showing how an\n"
        "   attacker actually reaches that function? Speculative 'what if' scenarios are false positives.\n"
        "8. For Leakage findings (`tee_category: Output & Metadata Leakage`): does the finding show\n"
        "   concrete evidence of output variation (response length, error detail, metadata) that depends\n"
        "   on secret data? Hypothetical timing or memory side-channel concerns are NOT sufficient —\n"
        "   only output length/metadata leakage qualifies for this category.\n\n"
        "Respond with JSON containing:\n"
        '- `false_positive_ids`: list of finding IDs to dismiss entirely\n'
        '- `severity_adjustments`: list of {"id", "recommended" (new severity), "reason"}\n'
        '- `dismissal_reasons`: dict mapping each dismissed finding ID to its specific reason\n'
        '- `adversarial_notes`: brief overall summary of decisions\n\n'
        "Be AGGRESSIVE in challenging findings. Default to keeping only findings with clear, "
        "exploitable attack paths in production code backed by concrete end-to-end invocation chains. "
        "If in doubt, DISMISS."
    )

    try:
        response = parse_with_retry(
            client,
            "You are a senior security auditor performing adversarial review. "
            "Your job is to identify FALSE POSITIVES and INFLATED SEVERITIES, not to find more issues. "
            "Be skeptical. Challenge every finding.",
            challenge_prompt,
            ReviewResponse,
            error_save_dir=None,
            temperature=temperature,
        )
    except Exception as e:
        logger.warning("Adversarial challenge failed: %s", str(e)[:200])
        return findings, []

    updated: list[Finding] = []
    challenge_log: list[str] = []

    for f in findings:
        if f.id in response.false_positive_ids:
            reason = response.dismissal_reasons.get(f.id, response.adversarial_notes[:200])
            updated.append(f.model_copy(update={
                "dismissed": True,
                "dismissal_reason": f"Adversarial review: false positive. {reason}",
            }))
            challenge_log.append(f"DISMISSED {f.id}: {f.title}")
            continue

        adjustment = next(
            (a for a in response.severity_adjustments if a.get("id") == f.id),
            None,
        )
        if adjustment:
            new_sev = _parse_enum(Severity, adjustment.get("recommended", ""), f.severity)
            updated.append(f.model_copy(update={"severity": new_sev}))
            challenge_log.append(
                f"SEVERITY {f.id}: {f.severity.value} -> {new_sev.value} ({adjustment.get('reason', '')})"
            )
            continue

        updated.append(f)

    return updated, challenge_log


def run_report_review(
    stage6_output: Stage6Output,
    invariants: list,
    repo_path: Path,
    client: LLMClient,
    results_dir: Path,
    max_iterations: int = MAX_RALPH_ITERATIONS,
    max_concurrent: int = 3,
    temperature: float = 0.3,
    zone_map_path: Path | None = None,
    key_components: list[str] | None = None,
) -> Stage6Output:
    """Run the ralph loop: review, verify invariants, refine report.

    Iterates up to max_iterations times:
    1. Review the current report for quality
    2. If quality < threshold, verify invariants against code to find new findings
    3. Refine the executive summary with review feedback
    4. Re-assemble the report
    """
    report = stage6_output.report
    review = ReviewResponse()  # track across iterations

    # Load zone_map for partition evidence in final render
    _zone_map = None
    if zone_map_path and zone_map_path.exists():
        try:
            from tee_audit.utils.call_graph import ZoneMap as _ZM
            _zone_map = _ZM.model_validate_json(zone_map_path.read_text())
        except Exception:
            pass

    for iteration in range(max_iterations):
        logger.info("Ralph iteration %d/%d: reviewing report", iteration + 1, max_iterations)

        # Step 1: Review
        review = _review_report(client, report)

        logger.info(
            "Ralph iteration %d: quality=%.2f, needs_refinement=%s",
            iteration + 1, review.quality_score, review.needs_refinement,
        )

        if not review.needs_refinement and review.quality_score >= QUALITY_THRESHOLD:
            logger.info("Report quality sufficient (%.2f >= %.2f), stopping ralph loop",
                        review.quality_score, QUALITY_THRESHOLD)
            break

        # Step 1b: Adversarial challenge of existing findings
        if report.findings:
            challenged_findings, challenge_log = _challenge_findings(
                report.findings, client, temperature=0.0,
            )
            report.findings = challenged_findings
            for entry in challenge_log:
                logger.info("Adversarial review: %s", entry)
            report.dashboard = _build_dashboard([f for f in report.findings if not f.dismissed and f.is_tee_relevant])

        # Step 2: If active findings are empty or weak, verify invariants against code
        active_findings = [f for f in report.findings if not f.dismissed]
        if len(active_findings) < len(invariants) // 2:
            # Only verify invariants not already covered by active findings or unknowns
            covered_inv_ids = {f.invariant_id for f in active_findings}
            covered_inv_ids |= {u.id.split("-", 1)[-1] for u in report.unknowns if "-" in u.id}
            uncovered = [inv for inv in invariants if inv.id not in covered_inv_ids]

            new_findings: list[Finding] = []
            new_guards: list[PositiveGuard] = []
            new_unknowns: list[Unknown] = []

            if not uncovered:
                logger.info("All invariants already covered, skipping re-verification")
            else:
                logger.info(
                    "Verifying %d uncovered invariants (of %d total)",
                    len(uncovered), len(invariants),
                )
                new_findings, new_guards, new_unknowns = _verify_invariants_parallel(
                    uncovered, repo_path, client, max_concurrent, temperature,
                )

            # Merge new results (deduplicate by invariant_id)
            existing_inv_ids = {f.invariant_id for f in report.findings}
            for f in new_findings:
                if f.invariant_id not in existing_inv_ids:
                    report.findings.append(f)
                    existing_inv_ids.add(f.invariant_id)

            existing_pg_ids = {pg.id for pg in report.positive_guards}
            for pg in new_guards:
                if pg.id not in existing_pg_ids:
                    report.positive_guards.append(pg)

            report.unknowns.extend(new_unknowns)

        # Step 2b: ALWAYS validate accumulated unknowns with broader context
        # (moved outside the sparse-findings conditional so unknowns are resolved every iteration)
        if report.unknowns:
            rv_findings, rv_guards, remaining = _validate_unknowns(
                report.unknowns, repo_path, client, invariants,
                max_concurrent=max_concurrent, temperature=temperature,
            )
            # Merge resolved findings/guards
            existing_inv_ids = {f.invariant_id for f in report.findings}
            for f in rv_findings:
                if f.invariant_id not in existing_inv_ids:
                    report.findings.append(f)
                    existing_inv_ids.add(f.invariant_id)
            existing_pg_ids = {pg.id for pg in report.positive_guards}
            for pg in rv_guards:
                if pg.id not in existing_pg_ids:
                    report.positive_guards.append(pg)
            # Replace unknowns with only the truly unresolved ones
            report.unknowns = remaining

            # Step 2c: Third pass for remaining unknowns
            if report.unknowns:
                resolved_ids: set[str] = set()
                for u in list(report.unknowns):
                    tp_findings, tp_guards, remaining_u = _third_pass_resolve(
                        u, repo_path, client, invariants, temperature,
                    )
                    existing_inv_ids = {f.invariant_id for f in report.findings}
                    for f in tp_findings:
                        if f.invariant_id not in existing_inv_ids:
                            report.findings.append(f)
                            existing_inv_ids.add(f.invariant_id)
                            resolved_ids.add(u.id)
                    existing_pg_ids = {pg.id for pg in report.positive_guards}
                    for pg in tp_guards:
                        if pg.id not in existing_pg_ids:
                            report.positive_guards.append(pg)
                            resolved_ids.add(u.id)
                if resolved_ids:
                    report.unknowns = [u for u in report.unknowns if u.id not in resolved_ids]

        # Rebuild dashboard (attack paths are now inline in findings)
        report.dashboard = _build_dashboard([f for f in report.findings if not f.dismissed and f.is_tee_relevant])

        # Step 3: Refine executive summary with feedback
        if review.critique:
            import re as _re
            raw_summary = _refine_executive_summary(client, report, review)
            # Strip any markdown headers from the LLM response
            report.executive_summary = _re.sub(r'^#{1,4}\s+.*$', '', raw_summary, flags=_re.MULTILINE).strip()

        logger.info(
            "Ralph iteration %d complete: %d findings, %d guards, %d unknowns",
            iteration + 1, len(report.findings), len(report.positive_guards), len(report.unknowns),
        )

    # Post-ralph safety net: verify invariants that still have no active finding AND no guard
    active_findings = [f for f in report.findings if not f.dismissed]
    covered_inv_ids = {f.invariant_id for f in active_findings}
    covered_inv_ids |= {pg.invariant_refs[0] for pg in report.positive_guards if pg.invariant_refs}
    uncovered = [inv for inv in invariants if inv.id not in covered_inv_ids]

    if uncovered:
        logger.info(
            "Post-ralph: verifying %d uncovered invariants (no finding, no guard)",
            len(uncovered),
        )
        pg_findings, pg_guards, pg_unknowns = _verify_invariants_parallel(
            uncovered, repo_path, client, max_concurrent, temperature,
        )
        for f in pg_findings:
            report.findings.append(f)
        for pg in pg_guards:
            report.positive_guards.append(pg)
        report.unknowns.extend(pg_unknowns)
        logger.info(
            "Post-ralph verification: +%d findings, +%d guards, +%d unknowns",
            len(pg_findings), len(pg_guards), len(pg_unknowns),
        )

    # Deduplicate guards: keep best guard per invariant (prefer complete > partial, longer evidence)
    best_guards: dict[str, PositiveGuard] = {}
    for pg in report.positive_guards:
        for inv_id in pg.invariant_refs:
            if inv_id == "UNKNOWN":
                continue
            existing = best_guards.get(inv_id)
            if existing is None:
                best_guards[inv_id] = pg
            elif pg.completeness_status == "complete" and existing.completeness_status != "complete":
                best_guards[inv_id] = pg
            elif len(pg.code_evidence) > len(existing.code_evidence):
                best_guards[inv_id] = pg
    report.positive_guards = list(best_guards.values())

    # Rebuild dashboard AFTER all post-ralph additions and dedup
    report.dashboard = _build_dashboard([f for f in report.findings if not f.dismissed and f.is_tee_relevant])

    # Final summary regeneration to reflect post-adversarial, post-dedup state
    try:
        raw_summary = _refine_executive_summary(client, report, review)
        import re as _re
        report.executive_summary = _re.sub(r'^#{1,4}\s+.*$', '', raw_summary, flags=_re.MULTILINE).strip()
        logger.info("Final executive summary regenerated to reflect dismissed findings")
    except Exception as e:
        logger.warning("Final summary regeneration failed: %s", str(e)[:200])

    # LLM Correctness Review — validate report quality before final write
    try:
        markdown_draft = _render_markdown_report(report, zone_map=_zone_map, repo_path=repo_path, key_components=key_components)
        reviewed_markdown = _llm_correctness_review(client, markdown_draft, report)
        if reviewed_markdown:
            markdown_draft = reviewed_markdown
            logger.info("LLM correctness review applied fixes to report")
    except Exception as e:
        logger.warning("LLM correctness review failed (using unreviewed report): %s", str(e)[:200])

    # Final write
    report_path = results_dir / "report.md"
    report_path.write_text(markdown_draft)

    json_path = results_dir / "report.json"
    json_path.write_text(report.model_dump_json(indent=2))

    logger.info("Ralph loop complete. Final report: %d findings, quality=%.2f",
                len(report.findings), review.quality_score)

    return Stage7Output(report=report, report_path=report_path, iterations_used=iteration + 1)


def _llm_correctness_review(
    client: LLMClient,
    markdown: str,
    report: Report,
) -> str | None:
    """LLM correctness review — check report for syntax and correctness issues.

    Returns the fixed markdown, or None if no changes needed.
    """
    prompt = load_prompt(
        "report_review_validator",
        report_markdown=markdown[:12000],
        finding_count=len([f for f in report.findings if not f.dismissed]),
        unknown_count=len(report.unknowns),
    )

    system_prompt = (
        "You are a technical report editor. Review the markdown report for: "
        "1) Table rendering issues (misaligned pipes, missing headers) "
        "2) Mermaid diagram syntax errors "
        "3) Missing trust boundary trace tables in TEE findings "
        "4) Broken markdown formatting "
        "Return the FULL corrected report markdown. If no changes needed, return the original."
    )

    try:
        response = client.complete(
            system=system_prompt,
            user=prompt,
            temperature=0.1,
        )
        fixed = response.strip()
        if fixed and len(fixed) > len(markdown) * 0.8:
            return fixed
        return None
    except Exception:
        return None


def _gather_broader_context(repo_path: Path, unknown: Unknown, inv: object | None) -> str:
    """Gather broader code context for an unknown — search all source dirs + docs."""
    # Extract keywords from what_was_checked and why_uncertain
    text = f"{unknown.what_was_checked} {unknown.why_uncertain}"
    search_kw = list(set(re.findall(r'\b\w{4,}\b', text.lower())))
    stop = {"that", "this", "with", "from", "were", "been", "have", "they", "them",
            "their", "which", "would", "could", "should", "about", "into", "through",
            "cannot", "without", "whether", "provided", "analysis", "source"}
    search_kw = [kw for kw in search_kw if kw not in stop]

    if not search_kw:
        return "[No additional source code found]"

    # Search ALL source directories, not just hardcoded ones
    scored_files = _search_all_source_dirs(repo_path, search_kw, set(), max_files=50)

    code_parts: list[str] = []
    seen: set[Path] = set()
    for _, f in scored_files[:10]:
        if f in seen:
            continue
        seen.add(f)
        block = _extract_relevant_blocks(f, repo_path, search_kw, max_blocks=3)
        if block:
            code_parts.append(block)
        if len(code_parts) >= 5:
            break

    # Also search docs and configs for context
    doc_results = _search_docs_and_configs(repo_path, search_kw, max_files=5)
    if doc_results:
        code_parts.append("## Documentation & Config Context\n" + "\n\n".join(doc_results))

    result = "\n\n".join(code_parts)
    if len(result) > 16000:
        result = result[:16000] + "\n...[truncated]"
    return result or "[No additional source code found]"


def _try_resolve_unknown(
    unknown: Unknown,
    repo_path: Path,
    client: LLMClient,
    invariants: list,
    temperature: float = 0.3,
) -> tuple[list[Finding], list[PositiveGuard], Unknown | None]:
    """Attempt to resolve an unknown with broader code context.

    Returns (findings, positive_guards, remaining_unknown).
    The remaining_unknown is None if fully resolved.
    """
    # Find the matching invariant
    inv = None
    if "-" in unknown.id:
        inv_id = unknown.id.split("-", 1)[-1]
        for i in invariants:
            if i.id == inv_id or i.id == f"INV-{inv_id}":
                inv = i
                break

    broader_code = _gather_broader_context(repo_path, unknown, inv)
    inv_desc = inv.description if inv else unknown.what_was_checked

    user_prompt = (
        f"Previously, an automated check could not verify this invariant:\n\n"
        f"**Invariant**: {inv_desc}\n\n"
        f"**Why uncertain**: {unknown.why_uncertain}\n\n"
        f"**Recommended steps**: {', '.join(unknown.recommended_steps)}\n\n"
        f"**Additional source code from the repository**:\n\n{broader_code}\n\n"
        f"Can you now determine whether this invariant is enforced, violated, or still uncertain? "
        f"If the code shows the guard is present, respond with a positive guard. "
        f"If you find a violation, respond with a finding. "
        f"If you genuinely still cannot tell, set resolved=false. "
        f"Make a BEST-EFFORT judgment. Only set resolved=false if there is genuinely ZERO evidence "
        f"in either direction. If there is ANY evidence of a guard, respond with a partial positive guard. "
        f"If there is ANY evidence of a violation, respond with a Weak finding. "
        f"Avoid marking as unknown unless you truly cannot tell.\n\n"
        f"Finding JSON format (ALL fields required — never leave any empty):\n"
        f'```json\n{{"title": "<max 8 words, concise label>", "severity": "Low|Info", "confidence": "Weak", '
        f'"attack_path": ["<step 1: how attacker reaches the vulnerable code>", "<step 2: what goes wrong>", "<step 3: impact>"], '
        f'"code_locations": [{{"file": "<path>", "line": <int>}}], '
        f'"remediation": "<specific fix recommendation>", '
        f'"impact": "<what happens if exploited, 1-2 sentences>", '
        f'"root_cause": "<why the vulnerability exists, 1 sentence>", '
        f'"preconditions": ["<what must be true for exploitation>"]}}\n```\n'
        f"Positive guard JSON format:\n"
        f'```json\n{{"title": "<max 8 words>", "description": "<1-3 sentences>", '
        f'"code_evidence": "<file:line>", "completeness": "partial|complete"}}\n```'
    )

    system_prompt = (
        "You are a security researcher performing a second-pass verification of TEE invariants. "
        "You have additional source code not available in the first pass. "
        "Be specific. Only report findings with code evidence. "
        "For findings: the title must be a SHORT LABEL (max 8 words), NOT a description. "
        "Put the detailed analysis in attack_path, impact, root_cause, and remediation. "
        "ALL finding fields must be populated — these are the most important parts of the audit report. "
        "Attack path steps should describe the exploitation scenario. "
        "No filler, no hedging."
    )

    try:
        response = parse_with_retry(
            client, system_prompt, user_prompt, ResolvedUnknownResponse,
            error_save_dir=None, temperature=temperature,
        )
    except Exception as e:
        logger.warning("Unknown resolution failed for %s: %s", unknown.id, str(e)[:200])
        return [], [], unknown

    findings: list[Finding] = []
    guards: list[PositiveGuard] = []

    if response.resolved and response.finding:
        f = response.finding
        severity = _parse_enum(Severity, f.get("severity", "Medium"), Severity.MEDIUM)
        confidence = _parse_enum(Confidence, f.get("confidence", "Likely"), Confidence.LIKELY)
        code_locs = _validate_code_locs(f.get("code_locations", []), repo_path)
        inv_id = inv.id if inv else "UNKNOWN"
        findings.append(Finding(
            id=f"RV-{unknown.id}",
            invariant_id=inv_id,
            severity=severity,
            confidence=confidence,
            title=f.get("title", f"Resolved: {unknown.what_was_checked[:80]}"),
            attack_path=f.get("attack_path", []),
            code_locations=code_locs,
            remediation=f.get("remediation", ""),
            trust_path_tier=TrustPathTier.CORE,
            cwe_id=f.get("cwe_id"),
            impact=f.get("impact", ""),
            root_cause=f.get("root_cause", ""),
            preconditions=f.get("preconditions", []),
            tee_category=family_to_taxonomy(inv.family) if inv else None,
            tee_dimension=inv.tee_dimension if inv else None,
            is_tee_relevant=True,
        ))
        logger.info("Resolved unknown %s to finding: %s", unknown.id, f.get("title", "")[:80])
        return findings, guards, None

    elif response.resolved and response.positive_guard:
        pg = response.positive_guard
        inv_id = inv.id if inv else "UNKNOWN"
        guards.append(PositiveGuard(
            id=f"PG-{unknown.id}",
            invariant_refs=[inv_id],
            trust_path_tier=TrustPathTier.CORE,
            title=pg.get("title", ""),
            description=pg.get("description", f"Guard confirmed: {unknown.what_was_checked[:100]}"),
            code_evidence=_coerce_evidence(pg.get("code_evidence", "")),
            completeness_status=pg.get("completeness", "partial"),
        ))
        logger.info("Resolved unknown %s to positive guard", unknown.id)
        return findings, guards, None

    # Still unresolved — keep the unknown but add resolution notes (only once)
    if response.resolution_notes:
        # Don't append duplicate second-pass notes across ralph iterations
        current = unknown.why_uncertain
        if "Second-pass notes:" not in current:
            updated_uncertain = f"{current}\n\nSecond-pass notes: {response.resolution_notes[:500]}"
        else:
            updated_uncertain = current
        updated_unknown = Unknown(
            id=unknown.id,
            title=unknown.title,
            what_was_checked=unknown.what_was_checked,
            why_uncertain=updated_uncertain,
            recommended_steps=unknown.recommended_steps,
        )
        return findings, guards, updated_unknown

    return findings, guards, unknown


def _third_pass_resolve(
    unknown: Unknown,
    repo_path: Path,
    client: LLMClient,
    invariants: list,
    temperature: float = 0.3,
) -> tuple[list[Finding], list[PositiveGuard], Unknown | None]:
    """Third pass: read full source file to resolve stubborn unknowns."""
    text = f"{unknown.what_was_checked} {unknown.why_uncertain}"
    search_kw = list(set(re.findall(r'\b\w{4,}\b', text.lower())))
    stop = {"that", "this", "with", "from", "were", "been", "have", "they", "them",
            "their", "which", "would", "could", "should", "about", "into", "through",
            "cannot", "without", "whether", "provided", "analysis", "source"}
    search_kw = [kw for kw in search_kw if kw not in stop]

    # Search all source directories for the most relevant file
    scored = _search_all_source_dirs(repo_path, search_kw, set(), max_files=50)

    if not scored or scored[0][0] < 3:
        return [], [], unknown

    best_file = scored[0][1]

    try:
        full_content = best_file.read_text(errors="ignore")
    except OSError:
        return [], [], unknown

    if len(full_content) > 15000:
        full_content = full_content[:15000] + "\n...[truncated]"

    # Find matching invariant
    inv = None
    if "-" in unknown.id:
        inv_id = unknown.id.split("-", 1)[-1]
        for i in invariants:
            if i.id == inv_id or i.id == f"INV-{inv_id}":
                inv = i
                break
    inv_desc = inv.description if inv else unknown.what_was_checked

    user_prompt = (
        f"FINAL ATTEMPT to resolve this unknown. You now have the FULL source file.\n\n"
        f"**Invariant**: {inv_desc}\n"
        f"**Why uncertain**: {unknown.why_uncertain}\n\n"
        f"**Full source file** ({best_file.relative_to(repo_path)}):\n```\n{full_content}\n```\n\n"
        f"You MUST make a judgment. Choose one:\n"
        f"- If the guard IS present: respond with a positive guard (completeness: partial or complete)\n"
        f"- If the guard is ABSENT: respond with a finding (severity: Low or Info)\n"
        f"- ONLY set resolved=false if this file is completely unrelated to the invariant.\n\n"
        f"Finding JSON format (ALL fields required — never leave any empty):\n"
        f'```json\n{{"title": "<max 8 words, concise label>", "severity": "Low|Info", "confidence": "Weak", '
        f'"attack_path": ["<step 1: how attacker reaches the vulnerable code>", "<step 2: what goes wrong>", "<step 3: impact>"], '
        f'"code_locations": [{{"file": "<path>", "line": <int>}}], '
        f'"remediation": "<specific fix recommendation>", '
        f'"impact": "<what happens if exploited, 1-2 sentences>", '
        f'"root_cause": "<why the vulnerability exists, 1 sentence>", '
        f'"preconditions": ["<what must be true for exploitation>"]}}\n```\n'
        f"Positive guard JSON format:\n"
        f'```json\n{{"title": "<max 8 words>", "description": "<1-3 sentences>", '
        f'"code_evidence": "<file:line>", "completeness": "partial|complete"}}\n```'
    )

    try:
        response = parse_with_retry(
            client,
            "You are a security researcher making a final determination. "
            "You have the full source file. Be decisive. "
            "For findings: the title must be a SHORT LABEL (max 8 words), NOT a description. "
            "Put the detailed analysis in attack_path, impact, root_cause, and remediation. "
            "ALL finding fields must be populated. No filler.",
            user_prompt,
            ResolvedUnknownResponse,
            error_save_dir=None,
            temperature=temperature,
        )
    except Exception as e:
        logger.warning("Third-pass resolution failed for %s: %s", unknown.id, str(e)[:200])
        return [], [], unknown

    findings: list[Finding] = []
    guards: list[PositiveGuard] = []
    inv_id = inv.id if inv else "UNKNOWN"

    if response.resolved and response.finding:
        f = response.finding
        severity = _parse_enum(Severity, f.get("severity", "Low"), Severity.LOW)
        confidence = _parse_enum(Confidence, f.get("confidence", "Weak"), Confidence.WEAK)
        code_locs = _validate_code_locs(f.get("code_locations", []), repo_path)
        findings.append(Finding(
            id=f"RV3-{unknown.id}",
            invariant_id=inv_id,
            severity=severity,
            confidence=confidence,
            title=f.get("title", f"Resolved: {unknown.what_was_checked[:80]}"),
            attack_path=f.get("attack_path", []),
            code_locations=code_locs,
            remediation=f.get("remediation", ""),
            trust_path_tier=TrustPathTier.CORE,
            cwe_id=f.get("cwe_id"),
            impact=f.get("impact", ""),
            root_cause=f.get("root_cause", ""),
            preconditions=f.get("preconditions", []),
            tee_category=family_to_taxonomy(inv.family) if inv else None,
            tee_dimension=inv.tee_dimension if inv else None,
            is_tee_relevant=True,
        ))
        logger.info("Third-pass resolved %s to finding: %s", unknown.id, f.get("title", "")[:80])
        return findings, guards, None

    elif response.resolved and response.positive_guard:
        pg = response.positive_guard
        guards.append(PositiveGuard(
            id=f"PG3-{unknown.id}",
            invariant_refs=[inv_id],
            trust_path_tier=TrustPathTier.CORE,
            title=pg.get("title", ""),
            description=pg.get("description", f"Third-pass guard: {unknown.what_was_checked[:100]}"),
            code_evidence=_coerce_evidence(pg.get("code_evidence", "")),
            completeness_status=pg.get("completeness", "partial"),
        ))
        logger.info("Third-pass resolved %s to positive guard", unknown.id)
        return findings, guards, None

    return findings, guards, unknown


def _validate_unknowns(
    unknowns: list[Unknown],
    repo_path: Path,
    client: LLMClient,
    invariants: list,
    max_concurrent: int = 3,
    temperature: float = 0.3,
) -> tuple[list[Finding], list[PositiveGuard], list[Unknown]]:
    """Try to resolve unknowns with a second pass using broader code context."""
    logger.info("Validating %d unknowns with broader context", len(unknowns))

    all_findings: list[Finding] = []
    all_guards: list[PositiveGuard] = []
    remaining_unknowns: list[Unknown] = []

    for u in unknowns:
        try:
            findings, guards, unknown = _try_resolve_unknown(
                u, repo_path, client, invariants, temperature,
            )
            all_findings.extend(findings)
            all_guards.extend(guards)
            if unknown is not None:
                remaining_unknowns.append(unknown)
        except Exception as e:
            logger.error("Unknown %s validation failed: %s", u.id, str(e)[:200])
            remaining_unknowns.append(u)

    resolved_count = len(unknowns) - len(remaining_unknowns)
    logger.info(
        "Unknown validation: %d/%d resolved (%d to findings, %d to guards)",
        resolved_count, len(unknowns),
        len(all_findings), len(all_guards),
    )
    return all_findings, all_guards, remaining_unknowns


def _verify_invariants_parallel(
    invariants: list,
    repo_path: Path,
    client: LLMClient,
    max_concurrent: int,
    temperature: float,
) -> tuple[list[Finding], list[PositiveGuard], list[Unknown]]:
    """Verify all invariants — sequential to avoid API rate limits."""
    all_findings: list[Finding] = []
    all_guards: list[PositiveGuard] = []
    all_unknowns: list[Unknown] = []

    for inv in invariants:
        try:
            findings, guards, unknowns = _verify_single_invariant(
                inv, repo_path, client, temperature,
            )
            all_findings.extend(findings)
            all_guards.extend(guards)
            all_unknowns.extend(unknowns)
        except Exception as e:
            logger.error("Invariant %s verification failed: %s", inv.id, str(e)[:200])

    return all_findings, all_guards, all_unknowns
