/**
 * @name TWE-BIND-001: Unbound attested subject authority
 * @description An authority grants trust for a registered subject, but the
 *              subject is not cryptographically/semantically bound to the
 *              attested claim that the verifier produced. Role/kind strings are
 *              catalog enum values (enum_registry.yml); the subject<->authority
 *              join uses the populated authoritySubjectOf fact.
 * @kind problem
 * @id web3-tee/trustir-go/twe-bind-001
 * @problem.severity warning
 * @tags tee trustir/twe-bind-001
 */
import go
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "attested_public_key") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "registered_agent") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "registration_acceptance") and
  GeneratedTrustFacts::authoritySubjectOf(auth, subject) and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "subject_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-BIND-001: registration authority subject not bound to attested public key",
  claim, "attested_public_key claim (verifier output)",
  subject, "registered_agent subject (request-controlled), no binding relation"
