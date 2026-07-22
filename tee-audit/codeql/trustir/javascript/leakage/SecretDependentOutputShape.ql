/**
 * @name TWE-LEAK-002: Secret-dependent output length or structure exposed
 * @description A secret source influences the length or shape of observable output
 *              (e.g. branching on a secret to vary output size), leaking information.
 * @kind path-problem
 * @id web3-tee/trustir-js/twe-leak-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-leak-002
 */
import javascript
import common.GeneratedTrustFacts

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    GeneratedTrustFacts::isTrustSource(source, "secret_source")
  }

  predicate isSink(DataFlow::Node sink) {
    GeneratedTrustFacts::isTrustSink(sink, "observable_sink")
  }

  predicate isBarrier(DataFlow::Node node) {
    GeneratedTrustFacts::hasSuppressor(node, "normalizer")
    or
    GeneratedTrustFacts::hasSuppressor(node, "constant_time")
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    GeneratedTrustFacts::isAdditionalTrustFlowStep(pred, succ)
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret-dependent output shape reaches an observable sink."
