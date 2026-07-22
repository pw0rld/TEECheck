/**
 * CryptoSanitizers.qll (Go)
 *
 * DETERMINISTIC, LLM-FREE recognition of cryptographically self-authenticating
 * operations. Data that has passed through one of these is no longer
 * "host-controlled": the output is constrained by cryptography (signature
 * recovery, public-key / signature / attestation / MAC verification), NOT by
 * the attacker's input bytes.
 *
 * Why this exists: the FLOW/LEAK taint queries model `hasSuppressor` only, and
 * the fact generator emits `hasSuppressor` as `none()`. Without a sanitizer
 * model, every benign self-authenticating pattern is mis-reported as
 * "host-controlled data reaches a security decision" — e.g. go-ethereum /
 * suave-geth recover the transaction sender via `Sender(signer, tx)` from the
 * ECDSA signature (V,R,S); the recovered address is NOT attacker-controllable,
 * yet a 27-path taint trace through it was reported as a `confirmed` finding.
 *
 * This allowlist is human-authored (a security engineer curates it, like the
 * prewritten queries). It is NOT produced by the LLM and does NOT emit
 * verdicts — it honors the core principle (LLM = semantic extraction only).
 * It is intentionally a NAME ALLOWLIST so it is auditable and zero-hallucination.
 *
 * These are wired into `isBarrier` of the Flow taint queries: a flow that must
 * pass through a self-authenticating derivation or a verification gate is not an
 * unguarded host->sink path. A real vulnerability (host input reaching a sink
 * WITHOUT an intervening crypto gate) still surfaces.
 *
 * Provides module `CryptoSanitizers` with:
 *   - isSignatureRecovery(DataFlow::Node n)  — output derived from a signature/key
 *   - isVerificationGate(DataFlow::Node n)    — boolean integrity check
 *   - isSanitizer(DataFlow::Node n)           — either of the above
 */

import go
import common.GeneratedTrustFacts

module CryptoSanitizers {
  /**
   * Self-authenticating DERIVATIONS. The RETURN VALUE is determined by a
   * signature / public key / attestation, not by the host-controlled argument
   * bytes flowing in, so taint must not propagate from argument to result.
   *
   * go-ethereum / suave-geth / FPC / generic:
   *   Sender(signer, tx)            — ECDSA signature -> from-address
   *   Signer.Sender(tx)             — method form of the above
   *   AsMessage(signer)             — builds message incl. signature-recovered From
   *   SigToPub / Ecrecover / ecrecover / recoverSigner / RecoverPubkey
   *                                  — low-level ECDSA recovery
   */
  predicate isSignatureRecovery(DataFlow::Node n) {
    exists(DataFlow::CallNode c |
      c.getTarget().getName() in [
        "Sender", "SigToPub", "Ecrecover", "ecrecover",
        "recoverSigner", "RecoverSigner", "RecoverPubkey", "AsMessage"
      ]
      and n = c)
  }

  /**
   * Verification GATES. A check whose result proves integrity of the supplied
   * data (signature, MAC, attestation quote, IAS report, seal). A sink reached
   * only after such a gate succeeds is guarded; treating the gate node as a
   * barrier conservatively stops taint from flowing "through" the check.
   */
  predicate isVerificationGate(DataFlow::Node n) {
    exists(DataFlow::CallNode c |
      c.getTarget().getName() in [
        "VerifySignature", "VerifyBytes", "VerifyMsg", "VerifyASN1",
        "CheckSig", "Verify", "VerifySeal", "VerifyAttestation",
        "VerifyQuote", "VerifyIASReport", "VerifyIASEvidence", "VerifyEvidence",
        "VerifyCertificate", "VerifyPeerCertificate", "MacVerify"
      ]
      and n = c)
  }

  predicate isSanitizer(DataFlow::Node n) {
    isSignatureRecovery(n) or isVerificationGate(n)
  }
}
