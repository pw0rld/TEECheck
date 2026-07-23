/**
 * @name TWE-FLOW-002: Secret/key material leaves TEE boundary unprotected
 * @description Secret or key material flows out of the TEE boundary into an untrusted
 *              sink without a protection guard.
 * @kind path-problem
 * @id web3-tee/trustir-js/twe-flow-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-flow-002
 */
import javascript
import common.GeneratedTrustFacts

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    GeneratedTrustFacts::isTrustSource(source, "secret_source")
  }

  predicate isSink(DataFlow::Node sink) {
    GeneratedTrustFacts::isTrustSink(sink, "boundary_exit")
  }

  predicate isBarrier(DataFlow::Node node) {
    GeneratedTrustFacts::hasSuppressor(node, "protection_guard")
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    GeneratedTrustFacts::isAdditionalTrustFlowStep(pred, succ)
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret material exits the TEE boundary without protection."
