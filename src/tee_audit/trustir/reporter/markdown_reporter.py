"""Markdown reporter for TrustIR findings.

Renders a HUMAN-READABLE report: per finding, what it means (TWE semantics), the
source->sink trace (the actual evidence), the solver-determined status, and the
LLM triage advisory (clearly labeled non-determining — status is the solver's).
Empty solver fields (authority_point_id etc.) are omitted rather than shown as
`None`. CodeQL owns locations; the LLM never sets status (its hint is advisory).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tee_audit.trustir.reporter.json_reporter import status_counts

# Display order for statuses in the summary table.
_STATUS_ORDER = [
    "confirmed",
    "violated_candidate",
    "configuration_dependent",
    "delegated",
    "guarded_elsewhere",
    "test_only",
    "out_of_scope",
    "unresolved",
]

# Plain-language meaning per TWE family (what the query looks for). Static text —
# no status, no LLM content; just explains the check.
_TWE_MEANING: dict[str, str] = {
    "TWE-FLOW-001": "Host-controlled input reaches an enclave security/authority decision (e.g. key derivation, signing, access control) — looks for a missing trust-boundary check on that path.",
    "TWE-FLOW-002": "Enclave secret/key material crosses to a host/network/log sink without an intervening protection guard (encryption, sealing, redaction).",
    "TWE-LEAK-001": "Secret-dependent enclave data reaches an observable sink (log, error, header, metric) without a normalizer (redaction / generic error wrapper).",
    "TWE-LEAK-002": "A secret-dependent branch influences observable output length/structure (a side-channel) without length padding / constant-length response.",
    "TWE-GUARD-001": "A verifier-success / appraisal guard is expected before an authority but is absent.",
    "TWE-GUARD-002": "A TCB status / debug-flag / QE-identity / collateral-freshness / revocation claim is consumed but the matching appraisal guard is absent before authority is granted.",
    "TWE-GUARD-003": "An authority consumes freshness-relevant evidence (nonce/timestamp/epoch) without an enforced freshness guard (replay risk).",
    "TWE-ATTEST-001": "Attestation claim-field binding / verifier-role issue.",
    "TWE-BIND-001": "Context-free output acceptance — output accepted without binding to the attested context.",
    "TWE-BIND-002": "Report-data to key binding missing.",
    "TWE-BIND-003": "Subject binding missing at an authority.",
    "TWE-STATE-001": "Sealed-state restore without version/continuity check.",
    "TWE-STATE-002": "Sealed-state version check missing.",
    "TWE-CONFIG-001": "Weak mode (debug/non-production) reachable to an authority.",
    "TWE-CONFIG-002": "Configuration-controlled security decision without a deployment guard.",
    "TWE-DESIGN-001": "Protected wrong component — guard on the wrong artifact.",
    "TWE-DESIGN-002": "Design-level protection gap.",
}

# Location path substrings that signal test/example/generated code (FP signal).
_FP_LOC_HINTS = ("/test", "/tests", "/testdata", "/fixtures", "/fakes/", "/mocks/",
                "/samples/", "/examples/", "/devenv/", "/e2e/", "_test.go", "_test.rs")


def _short(path: str, repo_root_hint: str = "") -> str:
    """Shorten an absolute/repo path for display (last 3 segments)."""
    p = (path or "").replace("\\", "/")
    for marker in ("sapphire-paratime/", "fabric-private-chaincode/",
                   "suave-geth/", "dcap-qvl/"):
        if marker in p:
            p = p.split(marker, 1)[1]
            break
    parts = [s for s in p.split("/") if s]
    return "/".join(parts[-3:]) if len(parts) > 3 else "/".join(parts)


def _loc_is_fp_signal(path: str) -> bool:
    p = (path or "").lower()
    return any(h in p for h in _FP_LOC_HINTS)


def _advisory(f: dict[str, Any]) -> str:
    """Render the LLM triage hint as an explicitly non-determining advisory."""
    hint = f.get("llm_vulnerable_hint")
    if hint is None:
        return "_no LLM triage ran for this finding_"
    if hint is True:
        return "**LLM judges this a plausible vulnerability** (advisory only; status above is authoritative)"
    if hint is False:
        return "**LLM judges this NOT a real vulnerability** (advisory only; status above is authoritative)"
    return f"LLM triage: `{hint}` (advisory only)"


def render_md(findings: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    repo = meta.get("repo") or "(repo)"

    def _is_fired(f: dict[str, Any]) -> bool:
        # A finding is "fired" if it has paths/locations OR a non-trivial status
        # (unresolved/None = the TWE evaluated to nothing). Fixtures may omit count.
        return f.get("count", 0) > 0 or f.get("status") not in (None, "", "unresolved")

    fired = [f for f in findings if _is_fired(f)]
    lines: list[str] = [
        f"# TrustIR Findings — {repo}",
        "",
        f"- Language: `{meta.get('language') or '?'}`  | Generated: {meta.get('generated_at') or 'n/a'}",
        f"- Total findings: **{len(findings)}**  | Fired: **{len(fired)}**. "
        "Status is solver-determined; LLM triage is advisory only.",
        "",
        "## Status summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    counts = status_counts(findings)
    for s in _STATUS_ORDER:
        if counts.get(s):
            lines.append(f"| `{s}` | {counts[s]} |")
    for s, n in counts.items():
        if s not in _STATUS_ORDER:
            lines.append(f"| `{s}` | {n} |")
    if not counts:
        lines.append("| (none) | 0 |")

    lines += ["", "---", "", "## Findings (fired)", ""]
    if not fired:
        lines += ["_No findings._", ""]
    for f in fired:
        twe = f.get("twe_id") or "?"
        summary = (f.get("summary") or "").replace("(@@)", "").strip()
        lines += [
            f"### {f.get('finding_id', twe)} — `{f.get('status')}`",
            "",
            f"**{twe}** ({f.get('family') or '?'}) — {f.get('count', 0)} path(s), "
            f"up to {f.get('path_hops', 0)} hop(s).",
            "",
            f"> **What this check looks for:** {_TWE_MEANING.get(twe, '(no description)')}",
            "",
        ]
        if summary:
            lines.append(f"_{summary}_")
            lines.append("")
        if f.get("note"):
            lines.append(f"**Note:** {f['note']}")
            lines.append("")
        # The trace is the actual evidence — render it prominently.
        path = f.get("path") or []
        if path:
            src = path[0]
            snk = path[-1]
            lines += [
                "**Source → sink trace (representative path):**",
                "",
                f"- **Source:** `{_short(src.get('file'))}:{src.get('line')}` — {src.get('message') or '(node)'}",
            ]
            for st in path[1:-1]:
                lines.append(f"- _via_ `{_short(st.get('file'))}:{st.get('line')}` — {st.get('message') or '(node)'}")
            if len(path) > 1:
                lines.append(f"- **Sink:** `{_short(snk.get('file'))}:{snk.get('line')}` — {snk.get('message') or '(node)'}")
            lines.append("")
        # Locations with a production/test flag (FP signal).
        locs = f.get("locations") or []
        if locs:
            shown = 0
            loc_lines: list[str] = []
            for l in locs:
                fp = _loc_is_fp_signal(l.get("file") or "")
                tag = " _(test/sample/generated — likely FP)_" if fp else ""
                loc_lines.append(f"  - `{_short(l.get('file'))}:{l.get('line')}`{tag}")
                shown += 1
                if shown >= 12:
                    rest = len(locs) - shown
                    if rest > 0:
                        loc_lines.append(f"  - … and {rest} more")
                    break
            lines += [f"**All locations ({len(locs)}):**", ""] + loc_lines + [""]
        # Advisory (LLM triage) — clearly non-determining.
        lines.append(f"**Advisory:** {_advisory(f)}")
        if f.get("applied_rule"):
            lines.append(f"- Solver rule: `{f.get('applied_rule')}`")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_md(text: str, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out


__all__ = ["render_md", "write_md"]
