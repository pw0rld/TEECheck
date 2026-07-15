/**
 * @name TWE-FLOW-001: Host-controlled data reaches enclave security decision
 * @description Host-controlled input flows into an enclave security/authority decision
 *              without an intervening TEE trust boundary check.
 * @kind path-problem
 * @id web3-tee/trustir-go/twe-flow-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-flow-001
 */
import go
import common.GeneratedTrustFacts
import common.CryptoSanitizers
import common.TypeBarriers
import common.TestScope

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string role |
      GeneratedTrustFacts::isTrustSource(source, role) and
      TestScope::isInProductionScope(source)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string role |
      GeneratedTrustFacts::isTrustSink(sink, role) and
      TestScope::isInProductionScope(sink)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(string s | GeneratedTrustFacts::hasSuppressor(node, s))
    or
    CryptoSanitizers::isSanitizer(node)
    or
    TypeBarriers::isBasicTypeBarrier(node)
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
