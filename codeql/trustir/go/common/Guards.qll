/**
 * Guards.qll (Go)
 *
 * Conservative guard/appraisal predicates. All definitions are intentionally
 * permissive-safe (prefer false negatives over false positives) and rely on the
 * GeneratedTrustFacts interface so the fact generator can refine them.
 *
 * Guard-kind strings passed to these predicates MUST be catalog enum values from
 * enum_registry.yml (guard_kind).
 *
 * Provides module `Guards` with:
 *   - isControlledByVerifierSuccess(DataFlow::Node auth)
 *   - hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind)
 *   - hasFreshnessGuard(DataFlow::Node auth)
 */

import go
import common.GeneratedTrustFacts

module Guards {
  /**
   * Holds when an authority point `auth` is governed by a verifier-success
   * guard. Conservative: true if a suppressor "checked_inside_verifier" or
   * "verifier_success" or "verifier_success_check" is recorded for the node.
   * (Suppressors are free-form strings emitted by the generator.)
   */
  predicate isControlledByVerifierSuccess(DataFlow::Node auth) {
    GeneratedTrustFacts::hasSuppressor(auth, "checked_inside_verifier")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "verifier_success")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "verifier_success_check")
  }

  /**
   * Holds when an authority point `auth` is protected by a guard of the given
   * kind. The kind MUST be a catalog guard_kind enum value (enum_registry.yml).
   * Conservative: true if a suppressor named after the guard kind holds
   * (e.g. "guard:<guard_kind>" or guard_kind itself).
   */
  predicate hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind) {
    GeneratedTrustFacts::hasSuppressor(auth, "guard:" + guard_kind)
    or
    GeneratedTrustFacts::hasSuppressor(auth, guard_kind)
  }

  /**
   * Holds when `auth` is protected by any catalog freshness guard kind.
   * (guard_kind enum values: nonce_freshness_check, timestamp_freshness_check,
   * epoch_freshness_check, collateral_freshness_check.)
   */
  predicate hasFreshnessGuard(DataFlow::Node auth) {
    hasRequiredAppraisalGuard(auth, "nonce_freshness_check")
    or
    hasRequiredAppraisalGuard(auth, "timestamp_freshness_check")
    or
    hasRequiredAppraisalGuard(auth, "epoch_freshness_check")
    or
    hasRequiredAppraisalGuard(auth, "collateral_freshness_check")
  }
}
