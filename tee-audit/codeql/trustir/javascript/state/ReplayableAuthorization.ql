/**
 * @name TWE-STATE-002: Replayable attestation result or authorization
 * @description An authorization artifact derived from attestation is accepted
 *              without a replay-cache/nonce freshness guard, enabling replay.
 * @kind problem
 * @id web3-tee/trustir-js/twe-state-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-state-002
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.Bindings
import common.TestScope

from DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth
where
  GeneratedTrustFacts::isClaimField(claim, "authorization_artifact") and
  GeneratedTrustFacts::isAuthoritySubject(subject, "freshness_field") and
  GeneratedTrustFacts::isAuthorityPoint(auth, "authorization_use") and
  not Bindings::hasAcceptedBindingRelation(claim, subject, auth) and
  not Guards::hasRequiredAppraisalGuard(auth, "replay_cache_or_nonce_guard") and
  not Guards::hasFreshnessGuard(auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "replay_protected") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-STATE-002: Replayable attestation-derived authorization (no freshness/replay guard)."
