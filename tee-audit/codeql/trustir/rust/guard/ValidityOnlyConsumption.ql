/**
 * @name TWE-GUARD-001: Validity-only attestation consumption
 * @description A relying party grants Web3 authority after checking only a generic
 *              verifier-success flag (valid / Ok / success) while ignoring the
 *              claim appraisal guards required for the operation (TCB status,
 *              measurement / signer allowlist, identity verification). Authority
 *              and guard kinds are catalog enum values (enum_registry.yml).
 * @kind problem
 * @id web3-tee/trustir-rust/twe-guard-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-001
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node auth
where
  isGuardRelevantAuthority(auth) and
  Guards::isControlledByVerifierSuccess(auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "verifier_success_check") and
  not Guards::hasRequiredAppraisalGuard(auth, "tcb_status_appraisal") and
  not Guards::hasRequiredAppraisalGuard(auth, "measurement_allowlist_check") and
  not Guards::hasRequiredAppraisalGuard(auth, "signer_allowlist_check") and
  not Guards::hasRequiredAppraisalGuard(auth, "report_data_integrity_check") and
  not Guards::hasRequiredAppraisalGuard(auth, "identity_verification") and
  not GeneratedTrustFacts::hasSuppressor(auth, "validity_only_consumption_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-GUARD-001: authority granted on verifier-success only; required claim appraisal absent."

/** Authority kinds (authority_kind) to which GUARD-001 applies per taxonomy. */
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
}
