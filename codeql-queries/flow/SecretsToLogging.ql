/**
 * @name Secrets reach logging or telemetry
 * @description Secrets, plaintext, attestation blobs, or decrypted state reach
 *              log statements or telemetry sinks.
 * @kind path-problem
 * @problem.severity error
 * @id tee-audit/flow/secrets-to-logging
 * @tags security
 *       tee
 *       flow
 */

import rust
import semmle.rust.dataflow.TaintTracking
import semmle.rust.Concepts
import DataFlow::PathGraph

class SecretsToLoggingConfig extends TaintTracking::Configuration {
  SecretsToLoggingConfig() { this = "SecretsToLogging" }

  override predicate isSource(DataFlow::Node source) {
    // Sources: variables/functions related to secrets, keys, plaintext
    exists(source.asExpr().(PathExpr).Target target |
      target.getName().toLowerCase().matches([
        "%secret%", "%private_key%", "%plaintext%", "%decrypted%",
        "%attestation%", "%quote%", "%report_data%"
      ])
    )
    or
    exists(source.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%decrypt%", "%unseal%", "%get_secret%", "%get_key%"
      ])
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sinks: logging macros and telemetry calls
    exists(sink.asExpr().(PathExpr).Target target |
      target.getName().toLowerCase().matches([
        "%println%", "%log%", "%debug%", "%info%", "%warn%", "%error%",
        "%trace%", "%write%", "%send%"
      ])
    )
    or
    exists(sink.asExpr().(FnCall).getName() name |
      name.toLowerCase().matches([
        "%log%", "%telemetry%", "%metric%", "%send%"
      ])
    )
  }
}

from SecretsToLoggingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Secret or sensitive data from $@ reaches a logging or telemetry sink.",
  source.getNode(), "this source"
