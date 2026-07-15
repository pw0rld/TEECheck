/**
 * @name TWE-DESIGN-001: Claimed TEE trust path has a non-TEE bypass
 * @description Structural candidate: a production-relevant authority point
 *              protecting a claimed security property is reachable without
 *              passing through a recorded TEE trust edge (no attestation-derived
 *              guard dominates it). Design queries have no dedicated enum, so the
 *              "claimed security property" is approximated by any production-
 *              relevant authority_kind, and the "TEE trust edge" by a recorded
 *              suppressor marking the path as TEE-enforced. Reported as a
 *              design_candidate.
 * @kind problem
 * @id web3-tee/trustir-rust/twe-design-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-design-001
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.Control
import common.TestScope

from DataFlow::Node auth, DataFlow::Node trustEdge
where
  isProductionRelevantAuthority(auth) and
  GeneratedTrustFacts::isAuthoritySubject(trustEdge, _) and
  Control::callableOf(auth) = Control::callableOf(trustEdge) and
  // Candidate: no recorded TEE trust edge dominates the authority in this callable,
  // i.e. there exists a path to the authority bypassing the TEE-attested subject.
  not Control::dominates(trustEdge, auth) and
  not GeneratedTrustFacts::hasSuppressor(auth, "tee_trust_path_enforced") and
  not GeneratedTrustFacts::hasSuppressor(auth, "design_001_resolved") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-DESIGN-001 (candidate): authority reachable without a TEE trust edge (possible bypass) (@@).",
  trustEdge, "attested subject in the same callable that does not dominate the authority."

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
  GeneratedTrustFacts::isAuthorityPoint(auth, "oracle_update")
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
}
