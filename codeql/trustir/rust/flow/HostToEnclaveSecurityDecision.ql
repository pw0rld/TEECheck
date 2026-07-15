/**
 * @name TWE-FLOW-001: Host-controlled data reaches enclave security decision
 * @description Host-controlled input flows into an enclave security/authority decision
 *              without an intervening TEE trust boundary check.
 * @kind path-problem
 * @id web3-tee/trustir-rust/twe-flow-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-flow-001
 */
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import common.GeneratedTrustFacts
import common.CryptoSanitizers
import common.TestScope

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string role |
      GeneratedTrustFacts::isTrustSource(source, role) and
      isHostControlledSourceRole(role) and
      TestScope::isInProductionScope(source)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string role |
      GeneratedTrustFacts::isTrustSink(sink, role) and
      isSecurityDecisionSinkRole(role) and
      TestScope::isInProductionScope(sink)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(string s | GeneratedTrustFacts::hasSuppressor(node, s))
    or
    CryptoSanitizers::isSanitizer(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    GeneratedTrustFacts::isAdditionalTrustFlowStep(pred, succ)
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Host-controlled data reaches enclave security decision."

/** Host-controlled / attacker-influenced source roles per TWE-FLOW-001.

    Inputs an attacker on the host/network can genuinely influence, so their
    reach into a security decision is a real flow concern. Attestation
    quote/report (external_attestation_input) are EXCLUDED: for a verifier they
    are public, hardware-generated, and cryptographically validated by the
    attestation protocol itself (the trust boundary), so a forged quote is a
    verification-bypass (TWE-ATTEST / TWE-DESIGN: a missing guard), not a
    host-controlled flow. Enclave-secret / internal roles are excluded too —
    they are not host-controlled (they belong to TWE-FLOW-002 / leakage). */
predicate isHostControlledSourceRole(string role) {
  role = "host_input"
  or
  role = "untrusted_rpc_input"
  or
  role = "peer_message"
  or
  role = "chain_input"
  or
  role = "user_supplied_data"
  or
  role = "host_controlled_config"
}

/** Security-decision sink roles per TWE-FLOW-001 (trust_sink_role — the
    consumption of trust data in a security/authority decision). Observable
    boundary-exit surfaces (logs, events, responses) belong to the leakage
    family, not here. */
predicate isSecurityDecisionSinkRole(string role) {
  role = "access_control_decision"
  or
  role = "enclave_call_input"
  or
  role = "key_release_target"
  or
  role = "key_derivation_input"
  or
  role = "signing_input"
  or
  role = "encryption_input"
  or
  role = "decryption_input"
  or
  role = "sealing_input"
  or
  role = "confidential_store_write"
}
