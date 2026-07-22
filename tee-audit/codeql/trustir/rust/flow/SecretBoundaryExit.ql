/**
 * @name TWE-FLOW-002: Secret or key material leaves TEE boundary without protection
 * @description Enclave-generated secret material crosses into a host / storage /
 *              network / log / RPC sink without an intervening protection guard
 *              (encryption, sealing, redaction, authenticated channel). Source and
 *              sink roles are catalog enum values (enum_registry.yml). The source is
 *              a secret-carrying trust-source role; the sink is an
 *              observable_sink_role / boundary-exit sink role.
 * @kind path-problem
 * @id web3-tee/trustir-rust/twe-flow-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-flow-002
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
      isSecretSourceRole(role) and
      TestScope::isInProductionScope(source)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string role |
      GeneratedTrustFacts::isTrustSink(sink, role) and
      isBoundaryExitSinkRole(role) and
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
select sink.getNode(), source, sink,
  "TWE-FLOW-002: enclave secret reaches host/network/log sink without protection guard."

/** Secret-carrying trust-source roles per TWE-FLOW-002 / TWE-LEAK-001. */
predicate isSecretSourceRole(string role) {
  role = "enclave_secret"
  or
  role = "enclave_private_key"
  or
  role = "key_material"
  or
  role = "sealed_state_content"
  or
  role = "user_confidential_input"
  or
  role = "private_key"
  or
  role = "confidential_result"
  or
  role = "enclave_internal_error"
  or
  role = "measurement_value"
}

/** Boundary-exit / observable sink roles per TWE-FLOW-002 + observable_sink_role. */
predicate isBoundaryExitSinkRole(string role) {
  role = "host_filesystem_write"
  or
  role = "log_output"
  or
  role = "host_log_output"
  or
  role = "rpc_error_message"
  or
  role = "http_response_body"
  or
  role = "http_header"
  or
  role = "grpc_status_detail"
  or
  role = "cli_output"
  or
  role = "event_emission"
  or
  role = "metrics_label"
  or
  role = "debug_trace"
  or
  role = "network_response"
  or
  role = "host_memory_buffer"
  or
  role = "rpc_response"
}
