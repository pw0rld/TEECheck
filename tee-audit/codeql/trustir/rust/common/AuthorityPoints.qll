/**
 * AuthorityPoints.qll (Rust)
 *
 * Library wrapper over GeneratedTrustFacts for authority-point concepts.
 * Conservative: all predicates delegate to the generated facts module.
 *
 * Provides module `AuthorityPoints` with:
 *   - isAuthorityPoint(DataFlow::Node n, string kind)
 *   - subjectBelongsToAuthority(DataFlow::Node subject, DataFlow::Node auth)
 */

import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts

module AuthorityPoints {
  /** An authority point of the given kind (e.g. "attestation_use", "policy_decision"). */
  predicate isAuthorityPoint(DataFlow::Node n, string kind) {
    GeneratedTrustFacts::isAuthorityPoint(n, kind)
  }

  /** Holds when `subject` is the authority-subject associated with authority `auth`. */
  predicate subjectBelongsToAuthority(DataFlow::Node subject, DataFlow::Node auth) {
    GeneratedTrustFacts::authoritySubjectOf(auth, subject)
  }
}
