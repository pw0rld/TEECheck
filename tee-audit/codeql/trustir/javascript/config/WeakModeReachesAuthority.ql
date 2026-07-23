/**
 * @name TWE-CONFIG-001: Debug/simulation/none-attestation mode reaches production authority
 * @description A weak (debug, simulation, or none-attestation) configuration source
 *              reaches a production authority point without a production guard.
 * @kind problem
 * @id web3-tee/trustir-js/twe-config-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-config-001
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.ConfigSources
import common.TestScope

from DataFlow::Node auth, DataFlow::Node source
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "production_authority") and
  (
    ConfigSources::isConfigSource(source, "weak_mode") or
    ConfigSources::isConfigSource(source, "debug_mode") or
    ConfigSources::isConfigSource(source, "simulation_mode") or
    ConfigSources::isConfigSource(source, "none_attestation")
  ) and
  ConfigSources::weakModeReachesAuthority(source, auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "production_guard") and
  not GeneratedTrustFacts::hasSuppressor(auth, "weak_mode_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-CONFIG-001: Weak/debug/simulation mode reaches production authority without a production guard."
