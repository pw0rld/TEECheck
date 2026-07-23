/**
 * @name TWE-GUARD-003: Missing freshness check before authority
 * @description An authority point consumes attestation evidence that carries a
 *              freshness-relevant claim field (nonce, timestamp, epoch, task_id)
 *              without an enforced freshness guard, allowing replay of stale
 *              evidence. Claim-field roles and guard kinds are catalog enum values
 *              (enum_registry.yml).
 * @kind problem
 * @id web3-tee/trustir-rust/twe-guard-003
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-003
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node freshnessClaim, DataFlow::Node auth, string claimRole
where
  isFreshnessClaimRole(claimRole) and
  GeneratedTrustFacts::isClaimField(freshnessClaim, claimRole) and
  isGuardRelevantAuthority(auth) and
  not hasMatchingFreshnessGuard(auth, claimRole) and
  not GeneratedTrustFacts::hasSuppressor(auth, "freshness_check_safe") and
  not GeneratedTrustFacts::hasSuppressor(freshnessClaim, "freshness_check_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth) and
  not TestScope::isTestOnlyPath(freshnessClaim) and
  not TestScope::isExampleOnlyPath(freshnessClaim)
select auth,
  "TWE-GUARD-003: authority applied without freshness check (replay risk) (@@).",
  freshnessClaim, claimRole + " freshness claim present without matching freshness guard."

/** Freshness-relevant claim_field_role values per TWE-GUARD-003. */
predicate isFreshnessClaimRole(string role) {
  role = "nonce"
  or
  role = "timestamp"
  or
  role = "epoch"
  or
  role = "task_id"
}

/** Authority kinds to which GUARD-003 applies. */
predicate isGuardRelevantAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "registration_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_release")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "proof_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_key_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "trusted_worker_update")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "oracle_update")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "settlement_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "policy_change")
}

/**
 * Holds when auth carries the freshness guard that covers the given freshness
 * claim role. Each disjunct binds claimRole. Collateral freshness is treated as
 * covering every freshness role.
 */
predicate hasMatchingFreshnessGuard(DataFlow::Node auth, string claimRole) {
  claimRole = "nonce" and Guards::hasRequiredAppraisalGuard(auth, "nonce_freshness_check")
  or
  claimRole = "timestamp" and Guards::hasRequiredAppraisalGuard(auth, "timestamp_freshness_check")
  or
  claimRole = "epoch" and Guards::hasRequiredAppraisalGuard(auth, "epoch_freshness_check")
  or
  claimRole = "task_id" and Guards::hasRequiredAppraisalGuard(auth, "nonce_freshness_check")
  or
  isFreshnessClaimRole(claimRole) and
  Guards::hasRequiredAppraisalGuard(auth, "collateral_freshness_check")
}
