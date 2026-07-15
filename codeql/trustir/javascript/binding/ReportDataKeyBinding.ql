/**
 * @name TWE-BIND-002: Public key not bound to attestation report data
 * @description A public key accepted by the runtime is not cryptographically bound
 *              to the attestation report data, allowing key substitution.
 * @kind problem
 * @id web3-tee/trustir-js/twe-bind-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-bind-002
 */
import javascript
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "attestation_report") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "public_key") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_use") and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "report_key_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-BIND-002: Public key is not bound to the attestation report data."
