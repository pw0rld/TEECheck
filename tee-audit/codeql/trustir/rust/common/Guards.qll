/**
 * Guards.qll (Rust)
 *
 * Guard/appraisal predicates. A guard protects an authority iff a call to a
 * guard function of the required kind is invoked in the authority's enclosing
 * callable AND that call structurally DOMINATES the authority node (every path
 * to the authority passes the guard). This is real CodeQL control-flow analysis
 * — the LLM never decides whether a guard protects an authority by name.
 *
 * Guard-kind strings passed to these predicates MUST be catalog enum values from
 * enum_registry.yml (guard_kind).
 *
 * Provides module `Guards` with:
 *   - isControlledByVerifierSuccess(DataFlow::Node auth)
 *   - hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind)
 *   - hasFreshnessGuard(DataFlow::Node auth)
 */

import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.Control

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
   * Holds when authority point `auth` is protected by a guard of the given
   * kind. Protection is verified STRUCTURALLY, not by name: there must be a call
   * `g` whose resolved target is a guard function of `guard_kind`, `g` is in the
   * same enclosing callable as `auth`, and `g`'s node DOMINATES `auth` (every
   * path to the authority passes the guard — see Control::dominates). This keeps
   * the guard→authority relationship in CodeQL's hands; the LLM only labels
   * WHICH functions are guards.
   */
  predicate hasRequiredAppraisalGuard(DataFlow::Node auth, string guard_kind) {
    exists(Call g, DataFlow::Node gn, Function gf |
      GeneratedTrustFacts::isGuardFunction(gf, guard_kind) and
      g.getStaticTarget() = gf and
      gn.asExpr() = g and
      Control::callableOf(auth) = g.getEnclosingCallable() and
      Control::dominates(gn, auth)
    )
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
