/**
 * CryptoSanitizers.qll (Rust)
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
 * "host-controlled data reaches a security decision".
 *
 * This allowlist is human-authored (a security engineer curates it, like the
 * prewritten queries). It is NOT produced by the LLM and does NOT emit
 * verdicts — it honors the core principle (LLM = semantic extraction only).
 * It is intentionally a NAME ALLOWLIST so it is auditable and zero-hallucination.
 *
 * Rust API notes (rust-all 0.2.4): a call is the top-level `Call` class
 * (`codeql.rust.elements.Call`), exposed via `import rust`). Its name is
 * obtained with `getTargetName()`. A `DataFlow::Node` wrapping the call's
 * result expression is recovered with `n.asExpr() = c`. There is no
 * `DataFlow::CallNode` in the Rust library.
 *
 * Provides module `CryptoSanitizers` with:
 *   - isSignatureRecovery(DataFlow::Node n)
 *   - isVerificationGate(DataFlow::Node n)
 *   - isSanitizer(DataFlow::Node n)
 */

import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts

module CryptoSanitizers {
  /**
   * Self-authenticating DERIVATIONS. The RETURN VALUE is determined by a
   * signature / public key / attestation, not by the host-controlled argument
   * bytes flowing in, so taint must not propagate from argument to result.
   *
   * Names cover: ECDSA recovery (recover_*), public-key recovery helpers, and
   * common Rust crypto-crate spellings (e.g. dcap-qvl, rust-crypto).
   */
  predicate isSignatureRecovery(DataFlow::Node n) {
    exists(Call c |
      c.getTargetName() in [
        "recover_signer", "recover_pubkey", "recover_pubkey_from_signature",
        "recover_address", "recover", "ecrecover",
        "RecoverPubkey", "RecoverSigner", "RecoverAddress",
        "signature_recover", "verify_and_recover"
      ]
      and n.asExpr() = c)
  }

  /**
   * Verification GATES. A check whose result proves integrity of the supplied
   * data (signature, MAC, attestation quote, IAS report, seal). A sink reached
   * only after such a gate succeeds is guarded; treating the gate node as a
   * barrier conservatively stops taint from flowing "through" the check.
   */
  predicate isVerificationGate(DataFlow::Node n) {
    exists(Call c |
      c.getTargetName() in [
        "verify_signature", "verify_bytes", "verify_msg", "verify_asn1",
        "check_sig", "verify", "verify_seal", "verify_attestation",
        "verify_quote", "verify_ias_report", "verify_ias_evidence", "verify_evidence",
        "verify_certificate", "verify_peer_certificate", "mac_verify",
        "verify_tcb", "verify_report", "verify_crl", "verify_collateral"
      ]
      and n.asExpr() = c)
  }

  predicate isSanitizer(DataFlow::Node n) {
    isSignatureRecovery(n) or isVerificationGate(n)
  }
}
