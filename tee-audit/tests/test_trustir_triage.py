"""Tests for the post-hoc triage filter (iteration 3).

Principle-critical: `apply_triage_status` must NEVER read `llm_vulnerable_hint`
for status. The hint is write-only (audit). These tests prove that directly.
"""

from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.triage import (
    apply_triage_status,
    extract_snippet,
    parse_triage_response,
    triage_findings,
)
from tee_audit.trustir.solver.status_classifier import classify


def _finding(status: str = "violated_candidate", family: str = "Flow", path=None, twe="twe-flow-001"):
    return {
        "finding_id": "F-x",
        "twe_id": twe,
        "family": family,
        "status": status,
        "path": path or [{"file": "a.go", "line": 1, "message": "source"}],
        "triage": {},
        "note": "",
    }


# --- Principle: llm_vulnerable_hint is NEVER read for status -------------------- #

def test_hint_true_does_not_promote_to_confirmed():
    """LLM says vulnerable (hint=True) but no guard model -> stays violated_candidate."""
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": False, "guarded_by": "", "confidence": "high",
           "likely_benign_reason": "", "llm_vulnerable_hint": True}
    out = apply_triage_status(f, sig, guard_confirmed=False)
    assert out["status"] == "violated_candidate"  # NOT promoted to confirmed
    assert out["llm_vulnerable_hint"] is True      # recorded for audit


def test_hint_false_does_not_clear_finding():
    """LLM says benign (hint=False) but the path still violated -> stays flagged."""
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": False, "guarded_by": "", "confidence": "high",
           "likely_benign_reason": "", "llm_vulnerable_hint": False}
    out = apply_triage_status(f, sig, guard_confirmed=False)
    assert out["status"] == "violated_candidate"  # NOT cleared by a benign hint


def test_hint_value_is_irregardless_of_status():
    """Same structured signal, different hint -> identical status (proves hint not read)."""
    base = {"self_authenticating": False, "guarded_by": "", "confidence": "low",
            "likely_benign_reason": ""}
    f = _finding(status="violated_candidate")
    out_true = apply_triage_status(f, {**base, "llm_vulnerable_hint": True})
    out_false = apply_triage_status(f, {**base, "llm_vulnerable_hint": False})
    assert out_true["status"] == out_false["status"]
    assert out_true["applied_rule"] == out_false["applied_rule"]


def test_status_differs_from_hint_fixture():
    """AC: >=1 fixture where final status != llm_vulnerable_hint (override fires).

    hint=True but status=violated_candidate (not confirmed) -> status != hint.
    """
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": False, "guarded_by": "", "confidence": "high",
           "likely_benign_reason": "", "llm_vulnerable_hint": True}
    out = apply_triage_status(f, sig, guard_confirmed=False)
    hint_bool = out["llm_vulnerable_hint"]
    # status 'violated_candidate' is not a boolean; map confirmed-ish for comparison
    status_is_confirmed = out["status"] == "confirmed"
    assert status_is_confirmed != hint_bool  # solver overrode the True hint


def test_sneaked_hint_in_finding_has_no_effect():
    """A hint key present directly on the finding dict does not change the outcome."""
    base = {"self_authenticating": False, "guarded_by": "", "confidence": "low",
            "likely_benign_reason": ""}
    clean = _finding(status="violated_candidate")
    poisoned = {**_finding(status="violated_candidate"), "llm_vulnerable_hint": True}
    a = apply_triage_status(clean, {**base, "llm_vulnerable_hint": False})
    b = apply_triage_status(poisoned, {**base, "llm_vulnerable_hint": False})
    assert a["status"] == b["status"]


# --- status_classifier (the obligation classifier) also ignores the hint key --- #

def test_status_classifier_ignores_hint_key():
    """Critic ask: status_classifier.classify must ignore a direct llm_vulnerable_hint."""
    raw_with_hint = {"family": "Flow", "violation": True, "out_of_scope": False,
                     "llm_vulnerable_hint": True}
    raw_without = {"family": "Flow", "violation": True, "out_of_scope": False}
    from tee_audit.trustir.models import FindingStatus
    a = classify(raw_with_hint, {}, {})
    b = classify(raw_without, {}, {})
    assert a == b == FindingStatus.CONFIRMED  # hint key had zero effect


# --- Structured observations DO influence status (these are evidence, not verdicts) --- #

def test_self_authenticating_sets_likely_benign():
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": True, "guarded_by": "", "confidence": "high",
           "likely_benign_reason": "ECDSA signature recovery", "llm_vulnerable_hint": True}
    out = apply_triage_status(f, sig, guard_confirmed=False)
    assert out["status"] == "violated_candidate"
    assert out["triage"]["likely_benign"] is True
    assert out["applied_rule"].startswith("triage_self_authenticating")


def test_guarded_by_alone_does_not_suppress():
    """An LLM guarded_by claim alone (guard_confirmed=False) must NOT suppress."""
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": False, "guarded_by": "if verifySig() {}", "confidence": "high",
           "likely_benign_reason": "", "llm_vulnerable_hint": False}
    out = apply_triage_status(f, sig, guard_confirmed=False)
    assert out["status"] == "violated_candidate"  # not guarded_elsewhere


def test_guarded_by_with_deterministic_confirmation_suppresses():
    f = _finding(status="violated_candidate")
    sig = {"self_authenticating": False, "guarded_by": "if verifySig() {}", "confidence": "high",
           "likely_benign_reason": "", "llm_vulnerable_hint": False}
    out = apply_triage_status(f, sig, guard_confirmed=True)
    assert out["status"] == "guarded_elsewhere"


# --- parse_triage_response robustness --- #

def test_parse_clean_json():
    s = parse_triage_response('{"self_authenticating": true, "guarded_by": "if v", '
                              '"likely_benign_reason": "r", "confidence": "high", '
                              '"llm_vulnerable_hint": false}')
    assert s["self_authenticating"] is True
    assert s["guarded_by"] == "if v"
    assert s["confidence"] == "high"
    assert s["llm_vulnerable_hint"] is False


def test_parse_fenced_json():
    raw = "```json\n{\"self_authenticating\": false, \"confidence\": \"medium\"}\n```"
    s = parse_triage_response(raw)
    assert s["self_authenticating"] is False
    assert s["confidence"] == "medium"
    assert s["llm_vulnerable_hint"] is None


def test_parse_malformed_is_conservative():
    s = parse_triage_response("not json at all")
    assert s["self_authenticating"] is False
    assert s["guarded_by"] == ""
    assert s["llm_vulnerable_hint"] is None


# --- extract_snippet --- #

def test_extract_snippet(tmp_path: Path):
    f = tmp_path / "a.go"
    f.write_text("\n".join(f"line {i}" for i in range(1, 21)))
    snip = extract_snippet(tmp_path, "a.go", 10, context=2)
    assert ">>> line 10" in snip
    assert "line 8" in snip and "line 12" in snip


def test_extract_snippet_missing_file(tmp_path: Path):
    assert extract_snippet(tmp_path, "nope.go", 5) == ""


# --- end-to-end with injected complete callable (no live LLM) --- #

def test_triage_findings_uses_heuristic_without_client():
    # Path whose terminal message is 'sender' -> heuristic flags self-authenticating.
    path = [{"file": "a.go", "line": 1, "message": "x"}, {"file": "a.go", "line": 9, "message": "sender"}]
    f = _finding(status="confirmed", family="Flow", path=path)
    out = triage_findings([f], repo_root=".", )  # no client -> heuristic fallback
    assert out[0]["triage"]["self_authenticating"] is True
    assert out[0]["status"] == "violated_candidate"


def test_triage_findings_with_injected_complete():
    def complete(system, user):
        return '{"self_authenticating": true, "guarded_by": "", "confidence": "medium", "llm_vulnerable_hint": false}'
    f = _finding(status="violated_candidate")
    out = triage_findings([f], repo_root=".", complete=complete)
    assert out[0]["triage"]["self_authenticating"] is True
    assert out[0]["llm_vulnerable_hint"] is False  # recorded
    assert out[0]["status"] == "violated_candidate"  # hint False did not clear
