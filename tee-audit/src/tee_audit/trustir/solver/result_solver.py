"""Iteration-2 solver: classify CodeQL results (with paths) into findings.

Where v1's solver consumed TrustIR obligations, v2 treats each TWE query as the
obligation check: a fired result is a violation. This produces one finding per
fired TWE, carrying the concrete source->sink path steps extracted from SARIF,
and reuses the 8-status classifier with the State/Design conservative cap.
"""

from __future__ import annotations

from typing import Any

from tee_audit.trustir.taxonomy import derive_family
from tee_audit.trustir.solver.status_classifier import classify_with_note

# Flow/Leakage findings where the reached value is SELF-AUTHENTICATING (derived
# from a signature / key / attestation, NOT attacker-controllable) must NOT be
# reported as `confirmed`. Example: go-ethereum/suave-geth recover the tx sender
# via `Sender(signer, tx)`; the recovered address is constrained by the ECDSA
# signature, yet a taint trace flags "host-controlled tx reaches the sender arg
# of evm.Call" as `confirmed`. CodeQL's object->field taint propagation through
# the signature cache (`tx.from.Load()`) defeats a name-allowlist barrier, so we
# instead DOWNGRADE the status honestly and leave the finding visible for triage.
_SELF_AUTH_TERMINAL = {"sender", "from"}  # terminal sink step message -> recovered identity
_SIG_RECOVERY_TOKENS = (  # path-step signals that the value was crypto-derived
    "transaction_signing", "signer.sender", "ecrecover", "sigtopub",
    "asmessage", "recoverpubkey", "verifysignature", "verifyattestation",
)


def _path_blob(path: list[dict[str, Any]]) -> str:
    return " ".join(f"{s.get('file') or ''} {s.get('message') or ''}".lower() for s in path)


def _is_self_authenticating(path: list[dict[str, Any]]) -> tuple[bool, str]:
    """True when the reached sink value is crypto-derived (not attacker-controlled)."""
    if not path:
        return False, ""
    terminal = (path[-1].get("message") or "").strip().lower()
    if terminal in _SELF_AUTH_TERMINAL:
        return True, f"terminal sink '{terminal}' is a signature-recovered identity"
    blob = _path_blob(path)
    hit = next((t for t in _SIG_RECOVERY_TOKENS if t in blob), None)
    if hit:
        return True, f"path crosses crypto self-authentication ('{hit}')"
    return False, ""


def solve_from_results(
    codeql_results: list[dict[str, Any]],
    suppressors: dict[str, bool] | None = None,
    coverage: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    """One finding per fired TWE; status via the 8-status classifier (+cap)."""
    suppressors = suppressors or {}
    coverage = coverage or {}
    findings: list[dict[str, Any]] = []
    for r in codeql_results:
        twe = r.get("twe_id", "")
        family = derive_family(twe)  # TaxonomyFamily
        error = r.get("error")
        violation = bool(r.get("violation"))

        if error:
            status, note = "unresolved", f"codeql_error:{error[:120]}"
        elif not violation:
            continue  # query did not fire -> no finding (not a false positive)
        else:
            raw = {"family": family.value, "violation": True, "out_of_scope": False}
            status_obj, note = classify_with_note(raw, suppressors, coverage)
            status = status_obj.value if hasattr(status_obj, "value") else str(status_obj)

        # Path reporting. A path-problem TWE can yield MANY source->sink results
        # (r["count"]). Previously the FIRST result's threadFlow was shown verbatim,
        # which (a) discarded the other paths and (b) produced misleading ~100+ step
        # blobs: a single SARIF threadFlow can weave through the same sink region
        # repeatedly. Real vulnerabilities live in SHORT paths where a guard is
        # demonstrably absent; long paths are where taint "explodes" through
        # storage/copy hops and semantic meaning is lost. So:
        #   - report path_count (how many distinct flows fired),
        #   - pick the SHORTEST path as the representative (fewest hops, highest
        #     signal; ties -> first),
        #   - collapse consecutive duplicate (file,line,message) steps so a single
        #     path is not padded with repeats.
        all_results = r.get("results", []) or []

        def _dedup(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            prev: tuple[Any, Any, Any] | None = None
            for s in steps:
                key = (s.get("file"), s.get("line"), s.get("message"))
                if key != prev:
                    out.append(s)
                    prev = key
            return out

        paths_raw = [res.get("path_steps") or [] for res in all_results]
        path_count = sum(1 for p in paths_raw if p) or r.get("count", 0)
        deduped = [_dedup(p) for p in paths_raw if p]
        path = min(deduped, key=len) if deduped else []

        locations: list[dict[str, Any]] = []
        seen_loc: set[tuple[Any, Any]] = set()
        for res in all_results:
            if res.get("file") or res.get("line"):
                k = (res.get("file"), res.get("line"))
                if k not in seen_loc:
                    seen_loc.add(k)
                    locations.append({"file": res.get("file"), "line": res.get("line")})

        # Honesty guard for Flow/Leakage: a fired taint query proves data reaches
        # the sink, NOT that the sink is attacker-controllable or unguarded. The
        # pipeline does not model guards, so it cannot honestly establish
        # `confirmed` (unguarded). Downgrade to violated_candidate (a real
        # candidate requiring human triage). When guard modeling is added, a
        # finding whose path has NO guard may be promoted back to confirmed.
        # Separately flag the self-authenticating case (signature/key/attestation
        # recovery) as likely-benign: the reached value is not attacker-controlled.
        triage: dict[str, Any] = {"family": family.value}
        if family.value in ("Flow", "Leakage") and status == "confirmed":
            self_auth, reason = _is_self_authenticating(path)
            triage["self_authenticating"] = self_auth
            status = "violated_candidate"
            parts = ["no guard model — candidate requiring human triage"]
            if self_auth:
                triage["likely_benign"] = True
                triage["reason"] = reason
                parts.append(
                    "self_authenticating_sink: " + reason +
                    " — reached value is not attacker-controlled"
                )
            note = (note + " | " if note else "") + "; ".join(parts)

        findings.append({
            "finding_id": f"F-{twe}",
            "twe_id": twe,
            "family": family.value,
            "status": status,
            "summary": (r.get("results", [{}])[0].get("message") if r.get("results") else None)
                       or f"{twe} violation",
            "path": path,
            "path_count": path_count,
            "path_hops": len(path),
            "locations": locations,
            "count": r.get("count", 0),
            "triage": triage,
            "note": note,
        })
    return findings


__all__ = ["solve_from_results"]
