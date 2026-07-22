/**
 * Bindings.qll (JavaScript)
 *
 * Conservative binding-relation predicates. These intentionally start permissive
 * (accept more bindings as "OK") so that only clearly-unbound cases are flagged,
 * and the fact generator can refine via GeneratedTrustFacts::authoritySubjectOf.
 *
 * Provides module `Bindings` with:
 *   - hasAcceptedBindingRelation(DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth)
 */

import javascript
import common.GeneratedTrustFacts

module Bindings {
  /**
   * Holds when `claim` is considered bound to `subject` at authority `auth`.
   * Conservative: accept if claim and subject are the same node, OR if the
   * generated facts explicitly associate them.
   */
  predicate hasAcceptedBindingRelation(DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth) {
    claim = subject
    or
    GeneratedTrustFacts::authoritySubjectOf(auth, subject)
    or
    GeneratedTrustFacts::hasSuppressor(auth, "binding_relation:" + "accepted")
  }
}
