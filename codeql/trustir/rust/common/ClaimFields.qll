/**
 * ClaimFields.qll (Rust)
 *
 * Library wrapper over GeneratedTrustFacts for claim-field concepts.
 * Conservative: delegates to the generated facts module.
 *
 * Provides module `ClaimFields` with:
 *   - isClaimField(DataFlow::Node n, string role)
 */

import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts

module ClaimFields {
  /** A data-flow node carrying a claim field with the given semantic role. */
  predicate isClaimField(DataFlow::Node n, string role) {
    GeneratedTrustFacts::isClaimField(n, role)
  }
}
