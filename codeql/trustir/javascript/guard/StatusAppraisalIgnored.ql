/**
 * @name TWE-GUARD-002: Attestation status or TCB appraisal ignored
 * @description An attestation status field or TCB appraisal result is read but not
 *              enforced before authority is applied.
 * @kind problem
 * @id web3-tee/trustir-js/twe-guard-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-002
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node auth
where
  (
    GeneratedTrustFacts::isAuthorityPoint(auth, "status_use") or
    GeneratedTrustFacts::isAuthorityPoint(auth, "tcb_appraisal_use") or
    GeneratedTrustFacts::isAuthorityPoint(auth, "attestation_use")
  ) and
  not Guards::hasRequiredAppraisalGuard(auth, "status_enforced") and
  not GeneratedTrustFacts::hasSuppressor(auth, "status_appraisal_ignored_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-GUARD-002: Attestation status / TCB appraisal is ignored before authority."
