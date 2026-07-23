/**
 * @name TWE-CONFIG-002: Host-controlled or development key enters trusted runtime authority
 * @description Host-controlled, injected, hardcoded, or development key material
 *              reaches a runtime / worker / signing / key-release authority
 *              without a dev-only or production-blocking guard. Key kinds are
 *              catalog enum values (security_mode_kind inject_key / use_dev_key,
 *              config_source_kind hardcoded_dev_key / test_key_material);
 *              authority kinds are authority_kind enum values.
 * @kind problem
 * @id web3-tee/trustir-go/twe-config-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-config-002
 */
import go
import common.GeneratedTrustFacts
import common.ConfigSources
import common.TestScope

from DataFlow::Node auth, DataFlow::Node source, string keyKind
where
  isRuntimeAuthority(auth) and
  isDevOrHostKey(source, keyKind) and
  ConfigSources::weakModeReachesAuthority(source, auth) and
  not hasProductionGuard(auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "dev_key_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-CONFIG-002: host-controlled/development key reaches runtime authority (@@).",
  source, keyKind + " key material reaches runtime authority."

/** Dev / host-controlled key kinds (security_mode_kind + config_source_kind enums). */
predicate isDevOrHostKey(DataFlow::Node source, string keyKind) {
  keyKind = "inject_key" and ConfigSources::isConfigSource(source, "inject_key")
  or
  keyKind = "use_dev_key" and ConfigSources::isConfigSource(source, "use_dev_key")
  or
  keyKind = "hardcoded_dev_key" and
  ConfigSources::isConfigSource(source, "hardcoded_dev_key")
  or
  keyKind = "test_key_material" and
  ConfigSources::isConfigSource(source, "test_key_material")
  or
  keyKind = "debug" and ConfigSources::isConfigSource(source, "debug")
  or
  keyKind = "simulation" and ConfigSources::isConfigSource(source, "simulation")
}

/** Runtime / key authority kinds (authority_kind enum). */
predicate isRuntimeAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_release")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_key_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "trusted_worker_update")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "confidential_input_acceptance")
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
  or
  GeneratedTrustFacts::hasSuppressor(auth, "dev_key_safe")
}
