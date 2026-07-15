/**
 * @name TWE-CONFIG-002: Host-controlled or development key enters trusted runtime authority
 * @description Host-controlled or development key material flows into a trusted
 *              runtime authority point without a production guard.
 * @kind problem
 * @id web3-tee/trustir-js/twe-config-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-config-002
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.ConfigSources
import common.TestScope

from DataFlow::Node auth, DataFlow::Node source
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_authority") and
  (
    ConfigSources::isConfigSource(source, "dev_key") or
    ConfigSources::isConfigSource(source, "host_controlled_key") or
    ConfigSources::isConfigSource(source, "key_material")
  ) and
  ConfigSources::weakModeReachesAuthority(source, auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "production_guard") and
  not GeneratedTrustFacts::hasSuppressor(auth, "dev_key_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-CONFIG-002: Host-controlled/development key reaches trusted runtime authority."
