/**
 * @name TWE-DESIGN-001: Claimed TEE trust path has a non-TEE bypass
 * @description Structural candidate: an authority point protecting a claimed
 *              security property is reachable from an entrypoint without passing
 *              through a TEE guard. Reported as a design_candidate.
 * @kind problem
 * @id web3-tee/trustir-js/twe-design-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-design-001
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.Control
import common.TestScope

from DataFlow::Node auth, DataFlow::Node entry
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "claimed_security_property") and
  GeneratedTrustFacts::isTrustSource(entry, "entrypoint") and
  // Candidate: no recorded TEE guard dominates the authority — i.e. there exists
  // a path to the authority bypassing recorded guards.
  not exists(DataFlow::Node guard |
    GeneratedTrustFacts::isAuthorityPoint(guard, "tee_guard") and
    Control::dominates(guard, auth)
  ) and
  not GeneratedTrustFacts::hasSuppressor(auth, "tee_trust_path_enforced") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-DESIGN-001 (candidate): authority reachable without passing a TEE guard (possible bypass path)."
