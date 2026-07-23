/**
 * @name TWE-BIND-002: Public key not bound to attestation report data
 * @description A public key is accepted with attestation evidence without checking
 *              that the key is bound into the report_data / user_data / nonce /
 *              transcript of the attestation report, enabling key substitution.
 *              The key subject is joined to the authority via authoritySubjectOf,
 *              and the binding check uses hasAcceptedBindingRelation (none() unless
 *              an explicit binding edge exists -> unbound cases flag, by design).
 *              All role/kind strings are catalog enum values (enum_registry.yml).
 * @kind problem
 * @id web3-tee/trustir-go/twe-bind-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-bind-002
 */
import go
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node reportField, DataFlow::Node keySubject, DataFlow::Node auth
where
  isReportDataField(reportField) and
  GeneratedTrustFacts::isAuthoritySubject(keySubject, "encryption_key") and
  isBindingRelevantAuthority(auth) and
  GeneratedTrustFacts::authoritySubjectOf(auth, keySubject) and
  not Bindings::hasAcceptedBindingRelation(reportField, keySubject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "report_data_key_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-BIND-002: public key accepted without binding to report_data / user_data / nonce (@@).",
  keySubject, "encryption_key subject accepted without report-data binding.",
  reportField, "attestation report field that should cover the key."

/** Claim-field roles that constitute attestation report binding material (claim_field_role enum). */
predicate isReportDataField(DataFlow::Node n) {
  GeneratedTrustFacts::isClaimField(n, "report_data")
  or
  GeneratedTrustFacts::isClaimField(n, "user_data")
  or
  GeneratedTrustFacts::isClaimField(n, "nonce")
  or
  GeneratedTrustFacts::isClaimField(n, "attested_public_key")
  or
  GeneratedTrustFacts::isClaimField(n, "runtime_public_key")
}

/** Authority kinds where a runtime key is accepted (authority_kind enum). */
predicate isBindingRelevantAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "registration_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_release")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_key_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "confidential_input_acceptance")
}
