/**
 * @name TWE-LEAK-001: Enclave secret/internal state reaches logs, errors, or metadata
 * @description A secret source flows into an observable sink (log, error message,
 *              metric, or metadata field) without a normalizer/sanitizer barrier.
 * @kind path-problem
 * @id web3-tee/trustir-js/twe-leak-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-leak-001
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
    GeneratedTrustFacts::hasSuppressor(node, "sanitizer")
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    GeneratedTrustFacts::isAdditionalTrustFlowStep(pred, succ)
  }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret material reaches a log, error, or metadata sink."
