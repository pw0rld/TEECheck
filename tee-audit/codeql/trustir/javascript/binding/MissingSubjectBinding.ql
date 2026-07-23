/**
 * @name TWE-BIND-001: Unbound attested subject authority
 * @description An authority is applied for an attested subject, but the subject is
 *              not cryptographically/semantically bound to the claim used at the
 *              authority point.
 * @kind problem
 * @id web3-tee/trustir-js/twe-bind-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-bind-001
 */
import javascript
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "attested_subject") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "attested_subject") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "attestation_use") and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "subject_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-BIND-001: Authority applied for a subject not bound to the attested claim."
