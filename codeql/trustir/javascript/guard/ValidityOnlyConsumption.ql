/**
 * @name TWE-GUARD-001: Validity-only attestation consumption
 * @description An attestation consumer only checks validity (is-well-formed) but
 *              ignores status/TCB appraisal before applying authority.
 * @kind problem
 * @id web3-tee/trustir-js/twe-guard-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-001
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node auth
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "attestation_use") and
  Guards::isControlledByVerifierSuccess(auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "status_appraisal") and
  not Guards::hasRequiredAppraisalGuard(auth, "tcb_appraisal") and
  not GeneratedTrustFacts::hasSuppressor(auth, "validity_only_consumption_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-GUARD-001: Attestation is consumed validity-only (status/TCB appraisal missing)."
