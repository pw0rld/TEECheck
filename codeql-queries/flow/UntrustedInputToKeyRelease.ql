/**
 * @name Untrusted input reaches key release or policy update
 * @description Untrusted artifact input reaches key release, admission,
 *              or policy update without sanitization or validation.
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/flow/untrusted-input-to-key-release
 * @tags security
 *       tee
 *       flow
 */

import rust
import semmle.rust.dataflow.TaintTracking
import DataFlow::PathGraph

class UntrustedToKeyReleaseConfig extends TaintTracking::Configuration {
  UntrustedToKeyReleaseConfig() { this = "UntrustedInputToKeyRelease" }

  override predicate isSource(DataFlow::Node source) {
    // Sources: external/user input, deserialized data, network input
    exists(source.asExpr().(PathExpr).Target target |
      target.getName().toLowerCase().matches([
        "%input%", "%request%", "%message%", "%packet%", "%buffer%",
        "%payload%", "%data%"
      ])
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sinks: key release, admission, policy update
    exists(sink.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%release%", "%export%", "%admit%", "%policy%", "%update%",
        "%set_key%", "%write_key%"
      ])
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Sanitizers: validation and sanitization functions
    exists(node.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%validate%", "%sanitize%", "%verify%", "%check%", "%parse%"
      ])
    )
  }
}

from UntrustedToKeyReleaseConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input from $@ reaches key release or policy update without sanitization.",
  source.getNode(), "this source"
