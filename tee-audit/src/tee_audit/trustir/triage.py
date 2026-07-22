"""Post-hoc triage filter (iteration 3 — IRIS post-hoc FP filter, adapted).

For each fired finding's source->sink path, extract the real source/sink code
snippets and ask the LLM to emit a STRUCTURED TRIAGE SIGNAL: observations on
whether the reached value is self-authenticating, whether a guard is present,
and a likely-benign reason. The LLM also emits ``llm_vulnerable_hint`` — but
that hint is WRITE-ONLY to the finding record: no code path reads it for status.

The deterministic function :func:`apply_triage_status` sets the finding's status
from the STRUCTURED observations + guard-dominance evidence ONLY, and may
override the hint in either direction (because it never reads the hint). This
honors the non-negotiable core principle: the LLM does semantic classification
only; it NEVER sets a finding's status.

The pre-existing heuristic ``_is_self_authenticating`` (result_solver) is the
FALLBACK signal when no LLM is available, so there is a single status-adjusting
path (this module), not two.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from tee_audit.llm.prompt_loader import load_prompt
from tee_audit.trustir.solver.result_solver import _is_self_authenticating

logger = logging.getLogger(__name__)

SNIPPET_CONTEXT_SIZE = 4

# The ONLY triage fields that may influence status. llm_vulnerable_hint is
# deliberately absent: it is write-only (recorded for audit, never read).
_STATUS_FIELDS = ("self_authenticating", "guarded_by", "confidence")


def extract_snippet(
    repo_root: str | Path, file_path: str | None, line: int | None, context: int = SNIPPET_CONTEXT_SIZE
) -> str:
    """Return ±`context` lines around `line` in `repo_root/file_path` with a marker.

    Returns "" if the file/line cannot be read. Paths are treated as relative to
    repo_root when possible (CodeQL emits repo-relative paths).
    """
    if not file_path or not line:
        return ""
    root = Path(repo_root)
    candidates = [Path(file_path), root / file_path]
    src: Path | None = next((p for p in candidates if p.exists()), None)
    if src is None:
        return ""
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out = []
    for i in range(start, end):
        lineno = i + 1
        marker = "  >>>" if lineno == line else "     "
        out.append(f"{lineno:>6}{marker} {lines[i]}")
    return "\n".join(out)


def _path_steps(findings_path: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return findings_path or []


def build_triage_prompt(
    finding: dict[str, Any], repo_root: str | Path
) -> tuple[str, str]:
    """Build (system, user) prompt for the finding using the trustir_triage template."""
    path = _path_steps(finding.get("path") or [])
    source_step = path[0] if path else {}
    sink_step = path[-1] if path else {}
    source = extract_snippet(repo_root, source_step.get("file"), source_step.get("line"))
    sink = extract_snippet(repo_root, sink_step.get("file"), sink_step.get("line"))
    intermediate = (
        "\n".join(
            f"- {s.get('file')}:{s.get('line')} {s.get('message') or ''}".strip()
            for s in path[1:-1]
        )
        or "(direct flow, no intermediate steps)"
    )
    user = load_prompt(
        "trustir_triage",
        twe_id=finding.get("twe_id", ""),
        family=finding.get("family", ""),
        source=source or "(unavailable)",
        sink=sink or "(unavailable)",
        source_loc=f"{source_step.get('file')}:{source_step.get('line')}",
        sink_loc=f"{sink_step.get('file')}:{sink_step.get('line')}",
        intermediate=intermediate,
    )
    # The template is the user message; system is a short role framing.
    system = (
        "You are a security expert performing post-hoc triage on a taint dataflow "
        "finding. Return STRICT JSON only."
    )
    return system, user


def parse_triage_response(text: str) -> dict[str, Any]:
    """Parse the LLM JSON response into a validated triage signal.

    Malformed / partial responses yield an empty (all-default) signal —
    conservative: no status change when the LLM is uncertain or unparseable.
    """
    signal: dict[str, Any] = {
        "self_authenticating": False,
        "guarded_by": "",
        "likely_benign_reason": "",
        "confidence": "low",
        "llm_vulnerable_hint": None,
    }
    if not text:
        return signal
    # Tolerate code-fenced JSON.
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`")
        if body.lower().startswith("json"):
            body = body[4:]
    # Find the first {...} block.
    lo, hi = body.find("{"), body.rfind("}")
    if lo < 0 or hi <= lo:
        return signal
    try:
        obj = json.loads(body[lo : hi + 1])
    except json.JSONDecodeError:
        return signal
    if not isinstance(obj, dict):
        return signal
    signal["self_authenticating"] = bool(obj.get("self_authenticating", False))
    gb = obj.get("guarded_by")
    signal["guarded_by"] = gb if isinstance(gb, str) else ""
    lr = obj.get("likely_benign_reason")
    signal["likely_benign_reason"] = lr if isinstance(lr, str) else ""
    conf = obj.get("confidence", "low")
    signal["confidence"] = conf if conf in ("low", "medium", "high") else "low"
    hint = obj.get("llm_vulnerable_hint")
    # Recorded for audit ONLY. No status code reads this.
    signal["llm_vulnerable_hint"] = bool(hint) if isinstance(hint, bool) else None
    return signal


def apply_triage_status(
    finding: dict[str, Any],
    signal: dict[str, Any],
    guard_confirmed: bool = False,
) -> dict[str, Any]:
    """Deterministically adjust a finding's status from a triage SIGNAL.

    Reads ONLY signal fields in :data:`_STATUS_FIELDS` (self_authenticating,
    guarded_by, confidence). NEVER reads ``llm_vulnerable_hint``: that field is
    write-only (recorded on the finding for audit). Because the hint is never
    read, the solver inherently overrides it in both directions.

    Rules:
      - self_authenticating -> status=violated_candidate + likely_benign flag
        (the reached value is not attacker-controlled; still a candidate).
      - guarded_by present AND deterministic guard_confirmed -> guarded_elsewhere.
      - otherwise: status unchanged; the prior solver status stands.

    `guard_confirmed` is a deterministic input (e.g. from a guard-dominance
    query), NOT an LLM judgment; default False so an LLM `guarded_by` claim
    alone never auto-suppresses a finding.
    """
    # Defensive: prove the hint is not consulted. If a caller sneaks it into the
    # finding or signal, it has no effect here.
    out = dict(finding)
    out.setdefault("triage", {})
    prior_status = out.get("status", "unresolved")

    # Record the hint for audit ONLY. It is not read below.
    out["llm_vulnerable_hint"] = signal.get("llm_vulnerable_hint")
    out["triage"]["self_authenticating"] = bool(signal.get("self_authenticating"))
    out["triage"]["guarded_by"] = signal.get("guarded_by") or ""
    out["triage"]["confidence"] = signal.get("confidence") or "low"
    if signal.get("likely_benign_reason"):
        out["triage"]["likely_benign_reason"] = signal["likely_benign_reason"]

    # NOTE: deliberately no reference to signal["llm_vulnerable_hint"] below.
    if signal.get("self_authenticating"):
        out["status"] = "violated_candidate"
        out["triage"]["likely_benign"] = True
        out["applied_rule"] = "triage_self_authenticating->violated_candidate"
        reason = signal.get("likely_benign_reason") or "self-authenticating reached value"
        out["note"] = ((out.get("note") or "") + " | " if out.get("note") else "") + (
            "triage: likely benign — " + reason
        )
    elif signal.get("guarded_by") and guard_confirmed:
        out["status"] = "guarded_elsewhere"
        out["applied_rule"] = "triage_guard_confirmed->guarded_elsewhere"
        out["note"] = ((out.get("note") or "") + " | " if out.get("note") else "") + (
            "triage: guard confirmed (" + str(signal.get("guarded_by"))[:80] + ")"
        )
    else:
        out["applied_rule"] = "triage_no_override"
        out["status"] = prior_status

    return out


def _heuristic_signal(finding: dict[str, Any]) -> dict[str, Any]:
    """Fallback signal (no LLM): reuse the deterministic self-auth detector."""
    self_auth, reason = _is_self_authenticating(finding.get("path") or [])
    return {
        "self_authenticating": self_auth,
        "guarded_by": "",
        "likely_benign_reason": reason,
        "confidence": "low",
        "llm_vulnerable_hint": None,
    }


def triage_findings(
    findings: list[dict[str, Any]],
    repo_root: str | Path,
    *,
    client: Any = None,
    complete: Callable[[str, str], str] | None = None,
    guard_confirmed_for: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run post-hoc triage over findings and apply deterministic status rules.

    Args:
        findings: solver findings (each with status, family, path, ...).
        repo_root: repo root for snippet extraction.
        client: optional LLMClient (uses client.complete). If None, the
            deterministic self-auth heuristic is used as the fallback signal
            (no LLM call).
        complete: optional `(system, user) -> str` callable; overrides client.
        guard_confirmed_for: optional `finding -> bool` deterministic predicate
            for guard dominance (e.g. wired to guard-query results). Defaults to
            "always False" so an LLM guarded_by never auto-suppresses.
    """
    out: list[dict[str, Any]] = []
    for f in findings:
        path = f.get("path") or []
        if not path:
            # No path to triage: leave status as-is, record empty signal.
            out.append(apply_triage_status(f, _heuristic_signal(f)))
            continue
        signal: dict[str, Any]
        if complete is not None or client is not None:
            try:
                system, user = build_triage_prompt(f, repo_root)
                if complete is not None:
                    raw = complete(system, user)
                else:
                    raw = client.complete(system, user, temperature=0)
                signal = parse_triage_response(raw)
            except Exception:  # noqa: BLE001 — triage must never crash the pipeline
                logger.exception("triage LLM call failed; falling back to heuristic")
                signal = _heuristic_signal(f)
        else:
            signal = _heuristic_signal(f)
        guard_confirmed = guard_confirmed_for(f) if guard_confirmed_for else False
        out.append(apply_triage_status(f, signal, guard_confirmed=guard_confirmed))
    return out


__all__ = [
    "SNIPPET_CONTEXT_SIZE",
    "extract_snippet",
    "build_triage_prompt",
    "parse_triage_response",
    "apply_triage_status",
    "triage_findings",
]
