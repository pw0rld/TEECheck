/**
 * Guards.qll (JavaScript)
 *
 * Conservative guard/appraisal predicates. All definitions are intentionally
 * permissive-safe (prefer false negatives over false positives) and rely on the
 * GeneratedTrustFacts interface so the fact generator can refine them.
 *
 * Provides module `Guards` with:
 *   - isControlledByVerifierSuccess(DataFlow::Node auth)
 *   - hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind)
 *   - hasFreshnessGuard(DataFlow::Node auth)
 */

import javascript
import common.GeneratedTrustFacts

module Guards {
  /**
   * Holds when an authority point `auth` is governed by a verifier-success
   * guard. Conservative: true if a suppressor "checked_inside_verifier" or
   * "verifier_success" is recorded for the node, OR if there exists another
   * recorded authority point of kind "verifier_success".
   */
  predicate isControlledByVerifierSuccess(DataFlow::Node auth) {
    GeneratedTrustFacts::hasSuppressor(auth, "checked_inside_verifier")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "verifier_success")
    or
    exists(DataFlow::Node g |
      GeneratedTrustFacts::isAuthorityPoint(g, "verifier_success") and
      g != auth
    )
  }

  /**
   * Holds when an authority point `auth` is protected by a guard of the given
   * kind. Conservative: true if a suppressor named after the guard kind holds
   * (e.g. "guard:<guard_kind>" or guard_kind itself).
   */
  predicate hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind) {
    GeneratedTrustFacts::hasSuppressor(auth, "guard:" + guard_kind)
    or
    GeneratedTrustFacts::hasSuppressor(auth, guard_kind)
  }

  /** Holds when `auth` is protected by a freshness check. */
  predicate hasFreshnessGuard(DataFlow::Node auth) {
    hasRequiredAppraisalGuard(auth, "freshness_check")
    or
    hasRequiredAppraisalGuard(auth, "freshness_guard")
  }
}
