/**
 * @name TWE-CONFIG-001: Debug / simulation / none-attestation mode reaches production authority
 * @description A weak security-mode configuration source (debug, simulation,
 *              mock_tee, none_attestation, skip_verification, allow_debug_enclave)
 *              reaches a production-relevant authority point without a production
 *              guard. Weak-mode and config-source kinds are catalog enum values
 *              (security_mode_kind / config_source_kind); authority kinds are
 *              authority_kind enum values.
 * @kind problem
 * @id web3-tee/trustir-go/twe-config-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-config-001
 */
import go
import common.GeneratedTrustFacts
import common.ConfigSources
import common.TestScope

from DataFlow::Node auth, DataFlow::Node source, string weakMode
where
  isProductionRelevantAuthority(auth) and
  isWeakModeSource(source, weakMode) and
  ConfigSources::weakModeReachesAuthority(source, auth) and
  not hasProductionGuard(auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "weak_mode_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-CONFIG-001: weak/debug/simulation mode reaches production authority (@@).",
  source, weakMode + " weak-mode source reaches production authority."

/** Weak security-mode kinds (security_mode_kind enum). */
predicate isWeakModeSource(DataFlow::Node source, string weakMode) {
  weakMode = "debug" and ConfigSources::isConfigSource(source, "debug")
  or
  weakMode = "simulation" and ConfigSources::isConfigSource(source, "simulation")
  or
  weakMode = "mock_tee" and ConfigSources::isConfigSource(source, "mock_tee")
  or
  weakMode = "none_attestation" and ConfigSources::isConfigSource(source, "none_attestation")
  or
  weakMode = "skip_verification" and ConfigSources::isConfigSource(source, "skip_verification")
  or
  weakMode = "allow_debug_enclave" and
  ConfigSources::isConfigSource(source, "allow_debug_enclave")
}

/** Production-relevant authority kinds (authority_kind enum). */
predicate isProductionRelevantAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "registration_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_release")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "secret_access")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "proof_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "trusted_worker_update")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_key_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "confidential_input_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "policy_change")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "settlement_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "state_restore_acceptance")
}

/** Production guards (free-form suppressors recorded by the fact generator). */
predicate hasProductionGuard(DataFlow::Node auth) {
  GeneratedTrustFacts::hasSuppressor(auth, "compile_time_exclusion")
  or
  GeneratedTrustFacts::hasSuppressor(auth, "production_chain_constant_false")
  or
  GeneratedTrustFacts::hasSuppressor(auth, "runtime_refusal")
  or
  GeneratedTrustFacts::hasSuppressor(auth, "deployment_policy_check")
  or
  GeneratedTrustFacts::hasSuppressor(auth, "feature_not_enabled_in_release")
  or
  GeneratedTrustFacts::hasSuppressor(auth, "production_guard")
}
