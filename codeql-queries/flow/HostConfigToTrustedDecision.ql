/**
 * @name Host-controlled input reaches trusted decision
 * @description Host-controlled configuration, time, or storage metadata reaches
 *              a trusted decision point inside a TEE boundary.
 * @kind path-problem
 * @problem.severity warning
 * @id tee-audit/flow/host-config-to-trusted-decision
 * @tags security
 *       tee
 *       flow
 */

import rust
import semmle.rust.dataflow.TaintTracking
import DataFlow::PathGraph

class HostConfigToTrustedConfig extends TaintTracking::Configuration {
  HostConfigToTrustedConfig() { this = "HostConfigToTrustedDecision" }

  override predicate isSource(DataFlow::Node source) {
    // Sources: external input, env vars, config, time, host-side data
    exists(source.asExpr().(PathExpr).Target target |
      target.getName().toLowerCase().matches([
        "%env%", "%config%", "%args%", "%timestamp%", "%time%",
        "%system_time%", "%host%"
      ])
    )
    or
    exists(source.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%env::%", "%read%", "%recv%", "%from_host%"
      ])
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sinks: attestation, admission, policy decisions, key release
    exists(sink.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%admit%", "%verify%", "%attest%", "%validate%",
        "%authorize%", "%release_key%", "%accept%"
      ])
    )
  }
}

from HostConfigToTrustedConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Host-controlled data from $@ reaches a trusted decision point.",
  source.getNode(), "this source"
