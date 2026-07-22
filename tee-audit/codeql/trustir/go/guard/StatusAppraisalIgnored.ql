/**
 * @name TWE-GUARD-002: Attestation status or TCB appraisal ignored
 * @description A TCB status, debug flag, QE identity, collateral freshness, or
 *              revocation status claim field is consumed (parsed / returned) but
 *              the corresponding appraisal guard is absent before authority is
 *              granted. Claim-field roles and guard kinds are catalog enum values
 *              (enum_registry.yml).
 * @kind problem
 * @id web3-tee/trustir-go/twe-guard-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-002
 */
import go
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node statusClaim, DataFlow::Node auth, string claimRole
where
  isStatusClaimRole(claimRole) and
  GeneratedTrustFacts::isClaimField(statusClaim, claimRole) and
  isGuardRelevantAuthority(auth) and
  not hasMatchingStatusGuard(auth, claimRole) and
  not GeneratedTrustFacts::hasSuppressor(auth, "status_appraisal_ignored_safe") and
  not GeneratedTrustFacts::hasSuppressor(statusClaim, "status_appraisal_ignored_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-GUARD-002: attestation status / TCB appraisal ignored before authority (@@).",
  statusClaim, claimRole + " claim field consumed without appraisal guard."

/** Status-bearing claim_field_role values per TWE-GUARD-002 (enum_registry has tcb_status, debug_flag). */
predicate isStatusClaimRole(string role) {
  role = "tcb_status"
  or
  role = "debug_flag"
  or
  role = "tee_type"
}

/** Authority kinds to which GUARD-002 applies (production-relevant authority). */
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
  GeneratedTrustFacts::isAuthorityPoint(auth, "confidential_input_acceptance")
}

/**
 * Holds when auth carries the appraisal guard that covers the given status claim
 * role. Each disjunct binds claimRole, so the predicate is functional in
 * (auth, claimRole). QE identity / collateral / revocation appraisals are treated
 * as covering every status role (they are general appraisal guards).
 */
predicate hasMatchingStatusGuard(DataFlow::Node auth, string claimRole) {
  claimRole = "tcb_status" and Guards::hasRequiredAppraisalGuard(auth, "tcb_status_appraisal")
  or
  claimRole = "debug_flag" and Guards::hasRequiredAppraisalGuard(auth, "production_mode_check")
  or
  claimRole = "tee_type" and Guards::hasRequiredAppraisalGuard(auth, "production_mode_check")
  or
  isStatusClaimRole(claimRole) and
  (
    Guards::hasRequiredAppraisalGuard(auth, "qe_identity_appraisal")
    or
    Guards::hasRequiredAppraisalGuard(auth, "collateral_freshness_check")
    or
    Guards::hasRequiredAppraisalGuard(auth, "crl_revocation_check")
  )
}
