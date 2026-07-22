/**
 * @name TWE-BIND-003: Context-free TEE output acceptance
 * @description A TEE output (proof / report / oracle result) is accepted at a
 *              settlement / proof / oracle authority without binding it to the
 *              expected context fields (chain_id, contract_address, task_id,
 *              epoch, runtime_hash), enabling cross-context replay. The proof
 *              subject is joined to the authority via authoritySubjectOf, and the
 *              binding check uses hasAcceptedBindingRelation (none() unless an
 *              explicit binding edge exists -> unbound cases flag, by design).
 *              All role/kind strings are catalog enum values (enum_registry.yml).
 * @kind problem
 * @id web3-tee/trustir-rust/twe-bind-003
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-bind-003
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.Bindings
import common.TestScope

from DataFlow::Node contextField, DataFlow::Node proofSubject, DataFlow::Node auth
where
  isContextField(contextField) and
  GeneratedTrustFacts::isAuthoritySubject(proofSubject, "proof_instance") and
  isContextBindingRelevantAuthority(auth) and
  GeneratedTrustFacts::authoritySubjectOf(auth, proofSubject) and
  not Bindings::hasAcceptedBindingRelation(contextField, proofSubject, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "context_free_output_binding_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-BIND-003: TEE output accepted without binding to context fields (@@).",
  proofSubject, "proof_instance subject accepted without context binding.",
  contextField, "context field that should be covered by the TEE output."

/** Context-binding claim_field_role values per TWE-BIND-003 (enum_registry). */
predicate isContextField(DataFlow::Node n) {
  GeneratedTrustFacts::isClaimField(n, "chain_id")
  or
  GeneratedTrustFacts::isClaimField(n, "contract_address")
  or
  GeneratedTrustFacts::isClaimField(n, "task_id")
  or
  GeneratedTrustFacts::isClaimField(n, "epoch")
  or
  GeneratedTrustFacts::isClaimField(n, "runtime_hash")
}

/** Authority kinds where a TEE output is accepted (authority_kind enum). */
predicate isContextBindingRelevantAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "proof_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "settlement_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "oracle_update")
}
