/**
 * @name TWE-GUARD-003: Missing freshness check before authority
 * @description An authority point consumes attestation output without verifying
 *              freshness (replay protection).
 * @kind problem
 * @id web3-tee/trustir-js/twe-guard-003
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-guard-003
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node auth
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "attestation_use") and
  not Guards::hasFreshnessGuard(auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "freshness_check") and
  not GeneratedTrustFacts::hasSuppressor(auth, "freshness_guard") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-GUARD-003: Authority applied without a freshness check (replay risk)."
