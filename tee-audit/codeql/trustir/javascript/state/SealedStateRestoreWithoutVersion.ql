/**
 * @name TWE-STATE-001: Sealed state restored without version/epoch continuity
 * @description Sealed state is restored without checking a version or epoch
 *              continuity guard, allowing rollback of protected state.
 * @kind problem
 * @id web3-tee/trustir-js/twe-state-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-state-001
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "state_object") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "state_version") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "state_restore") and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "continuity_guard") and
  not GeneratedTrustFacts::hasSuppressor(auth, "continuity_check") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-STATE-001: Sealed state restored without version/epoch continuity check."
