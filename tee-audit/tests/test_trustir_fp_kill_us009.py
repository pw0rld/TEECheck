"""US-009 regression: the suave FLOW-001 signature-recovery FP is killed.

This proves the FP-kill STRUCTURALLY at the solver + triage layer (no CodeQL, no
LLM) so it runs in milliseconds and guards the mechanism independently of the
slow end-to-end run. It feeds solve_from_results a FLOW-001 result whose path
crosses ECDSA signature recovery (the original FP shape: host-controlled tx ->
Sender(signer,tx) -> recovered `from` -> evm.Call) and asserts the finding is
NOT `confirmed` — it must be `violated_candidate` + self_authenticating.

The empirical confirmation on the real suave-geth DB (scripts/trustir_e2e_validate
/ the `trustir` CLI run) complements this.
"""

from __future__ import annotations

from tee_audit.trustir.solver.result_solver import solve_from_results
from tee_audit.trustir.triage import triage_findings


def _flow001_result_signature_recovery() -> dict:
    """A FLOW-001 fired result whose path crosses ECDSA signature recovery."""
    return {
        "twe_id": "twe-flow-001",
        "violation": True,
        "count": 1,
        "results": [
            {
                "file": "core/tx.go",
                "line": 10,
                "message": "host-controlled transaction",
                # Path weaves through the signature-recovery derivation that
                # CryptoSanitizers barriers and the honesty downgrade catches.
                "path_steps": [
                    {"file": "core/tx.go", "line": 10, "message": "transaction_signing"},
                    {"file": "crypto/crypto.go", "line": 88, "message": "SigToPub"},
                    {"file": "crypto/crypto.go", "line": 120, "message": "ecrecover"},
                    {"file": "core/tx.go", "line": 200, "message": "sender"},  # terminal
                ],
            }
        ],
    }


def test_flow001_signature_recovery_not_confirmed():
    """The signature-recovery FP must never be `confirmed`."""
    findings = solve_from_results([_flow001_result_signature_recovery()])
    assert findings, "FLOW-001 should produce a finding"
    f = findings[0]
    assert f["twe_id"] == "twe-flow-001"
    assert f["status"] != "confirmed", f"FP not killed: status={f['status']}"
    assert f["status"] == "violated_candidate"
    # Triage (heuristic fallback, no client) flags it self-authenticating / likely benign.
    triaged = triage_findings(findings, repo_root=".")  # no client -> deterministic heuristic
    t = triaged[0]
    assert t["status"] != "confirmed"
    assert t["triage"].get("self_authenticating") is True
    assert t["triage"].get("likely_benign") is True
    # The hint is write-only and absent here (no LLM); status set deterministically.
    assert t.get("llm_vulnerable_hint") in (None,)


def test_flow001_real_unguarded_path_stays_candidate():
    """A genuine host->sink path with NO signature recovery stays a candidate
    (violated_candidate, not auto-suppressed) — recall is preserved."""
    result = {
        "twe_id": "twe-flow-001",
        "violation": True,
        "count": 1,
        "results": [
            {
                "file": "eth/api_backend.go", "line": 472, "message": "host input",
                "path_steps": [
                    {"file": "eth/api_backend.go", "line": 472, "message": "input param"},
                    {"file": "eth/api_backend.go", "line": 480, "message": "DoCall"},
                    {"file": "core/vm/call.go", "line": 99, "message": "enclave execute"},
                ],
            }
        ],
    }
    findings = solve_from_results([result])
    f = findings[0]
    # Not self-authenticating -> NOT flagged likely_benign; still a real candidate.
    assert f["status"] == "violated_candidate"
    triaged = triage_findings(findings, repo_root=".")
    assert triaged[0]["status"] == "violated_candidate"
    assert not triaged[0]["triage"].get("likely_benign")
