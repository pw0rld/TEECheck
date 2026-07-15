/**
 * @name TWE-LEAK-001: Enclave secret / internal state reaches logs, errors, or metadata
 * @description Secret-dependent enclave data or internal state reaches an
 *              observable sink (log, error message, header, event, metric)
 *              without a normalizer (redaction / generic error wrapper / error
 *              code mapping / metadata suppression). Source roles are
 *              secret-carrying trust-source roles; sink roles are
 *              observable_sink_role catalog enum values (enum_registry.yml).
 * @kind path-problem
 * @id web3-tee/trustir-rust/twe-leak-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-leak-001
 */
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import common.GeneratedTrustFacts
import common.TestScope

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string role |
      GeneratedTrustFacts::isTrustSource(source, role) and
      isLeakSecretSourceRole(role) and
      TestScope::isInProductionScope(source)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string role |
      GeneratedTrustFacts::isTrustSink(sink, role) and
      isObservableSinkRole(role) and
      TestScope::isInProductionScope(sink)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(string s | GeneratedTrustFacts::hasSuppressor(node, s)) and
    (
      GeneratedTrustFacts::hasSuppressor(node, "generic_error_wrapper")
      or
      GeneratedTrustFacts::hasSuppressor(node, "redaction")
      or
      GeneratedTrustFacts::hasSuppressor(node, "error_code_mapping")
      or
      GeneratedTrustFacts::hasSuppressor(node, "metadata_suppression")
      or
      GeneratedTrustFacts::hasSuppressor(node, "normalizer")
      or
      GeneratedTrustFacts::hasSuppressor(node, "sanitizer")
    )
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
  "TWE-LEAK-001: enclave secret / internal state reaches an observable log/error/metadata sink."

/** Secret-source roles per TWE-LEAK-001. */
predicate isLeakSecretSourceRole(string role) {
  role = "enclave_secret"
  or
  role = "private_key"
  or
  role = "user_confidential_input"
  or
  role = "sealed_state_content"
  or
  role = "enclave_internal_error"
  or
  role = "measurement_value"
  or
  role = "key_material"
}

/** Observable sink roles (observable_sink_role enum). */
predicate isObservableSinkRole(string role) {
  role = "log_output"
  or
  role = "rpc_error_message"
  or
  role = "http_response_body"
  or
  role = "http_header"
  or
  role = "grpc_status_detail"
  or
  role = "event_emission"
  or
  role = "metrics_label"
  or
  role = "debug_trace"
}
