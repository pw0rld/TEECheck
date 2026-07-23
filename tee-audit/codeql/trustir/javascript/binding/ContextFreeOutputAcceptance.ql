/**
 * @name TWE-BIND-003: Context-free TEE output acceptance
 * @description TEE output is accepted without binding it to the expected context
 *              fields (challenge, channel, peer), enabling cross-context replay.
 * @kind problem
 * @id web3-tee/trustir-js/twe-bind-003
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-bind-003
 */
import javascript
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "tee_output") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "context_field") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "tee_output_use") and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "context_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-BIND-003: TEE output accepted without binding to context fields."
