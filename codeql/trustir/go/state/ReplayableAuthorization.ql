/**
 * @name TWE-STATE-002: Replayable attestation result or authorization
 * @description An old attestation result, authorization, signature, or key-release
 *              approval (a freshness_token / nonce_cache / epoch_state /
 *              replay_trace artifact) reaches an authority without a replay /
 *              freshness guard, enabling replay. State-object kinds are catalog
 *              enum values (state_object_kind); freshness guards are guard_kind
 *              enum values.
 * @kind problem
 * @id web3-tee/trustir-go/twe-state-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-state-002
 */
import go
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node authzArtifact, DataFlow::Node auth, string stateKind
where
  isReplayableArtifact(authzArtifact, stateKind) and
  isReplayRelevantAuthority(auth) and
  not Guards::hasFreshnessGuard(auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "replay_protected") and
  not GeneratedTrustFacts::hasSuppressor(authzArtifact, "replay_protected") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-STATE-002: replayable attestation-derived authorization reaches authority (@@).",
  authzArtifact, stateKind + " authorization artifact without replay/freshness guard."

/** Replayable authorization-artifact state objects (state_object_kind enum). */
predicate isReplayableArtifact(DataFlow::Node n, string kind) {
  kind = "freshness_token" and GeneratedTrustFacts::isClaimField(n, "freshness_token")
  or
  kind = "nonce_cache" and GeneratedTrustFacts::isClaimField(n, "nonce_cache")
  or
  kind = "epoch_state" and GeneratedTrustFacts::isClaimField(n, "epoch_state")
  or
  kind = "replay_trace" and GeneratedTrustFacts::isClaimField(n, "replay_trace")
}

/** Authority kinds where an attestation-derived authorization is accepted. */
predicate isReplayRelevantAuthority(DataFlow::Node auth) {
  GeneratedTrustFacts::isAuthorityPoint(auth, "proof_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "key_release")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "settlement_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "runtime_key_acceptance")
  or
  GeneratedTrustFacts::isAuthorityPoint(auth, "policy_change")
}
