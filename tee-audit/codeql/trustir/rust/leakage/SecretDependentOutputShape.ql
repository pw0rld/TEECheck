/**
 * @name TWE-LEAK-002: Secret-dependent output length or structure exposed
 * @description Output length, response shape, or metadata structure varies based
 *              on enclave-secret-dependent state (a secret-dependent branch
 *              influences observable output size or structure) without a
 *              normalizer (length padding / constant-length response / generic
 *              error wrapper). Source roles are secret/secret-branch
 *              trust-source roles; sink roles are observable_sink_role catalog
 *              enum values (enum_registry.yml).
 * @kind path-problem
 * @id web3-tee/trustir-rust/twe-leak-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-leak-002
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
      isLeakShapeSourceRole(role) and
      TestScope::isInProductionScope(source)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string role |
      GeneratedTrustFacts::isTrustSink(sink, role) and
      isLeakShapeSinkRole(role) and
      TestScope::isInProductionScope(sink)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    GeneratedTrustFacts::hasSuppressor(node, "length_padding")
    or
    GeneratedTrustFacts::hasSuppressor(node, "constant_length_response")
    or
    GeneratedTrustFacts::hasSuppressor(node, "generic_error_wrapper")
    or
    GeneratedTrustFacts::hasSuppressor(node, "normalizer")
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
  "TWE-LEAK-002: secret-dependent branch controls observable output size/structure."

/** Secret / secret-branch source roles per TWE-LEAK-002. */
predicate isLeakShapeSourceRole(string role) {
  role = "user_confidential_input"
  or
  role = "confidential_result"
  or
  role = "sealed_state_content"
  or
  role = "secret_dependent_branch"
  or
  role = "enclave_secret"
  or
  role = "key_material"
}

/** Observable sink roles per TWE-LEAK-002 (observable_sink_role enum subset). */
predicate isLeakShapeSinkRole(string role) {
  role = "http_response_body"
  or
  role = "rpc_error_message"
  or
  role = "grpc_status_detail"
  or
  role = "event_emission"
  or
  role = "host_filesystem_write"
}
