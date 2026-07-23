/**
 * @name TWE-DESIGN-002: TEE protects the wrong component for the claimed property
 * @description Structural candidate: a component is marked as TEE-protected, but a
 *              critical component for the claimed security property is recorded as
 *              unprotected and is applied as authority. Reported as a design_candidate.
 * @kind problem
 * @id web3-tee/trustir-js/twe-design-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-design-002
 */
import javascript
import common.GeneratedTrustFacts
import common.Guards
import common.TestScope

from DataFlow::Node auth, DataFlow::Node critical
where
  GeneratedTrustFacts::isAuthorityPoint(auth, "claimed_security_property") and
  GeneratedTrustFacts::isTrustSink(critical, "unprotected_critical_component") and
  not exists(DataFlow::Node prot |
    GeneratedTrustFacts::isTrustSource(prot, "trusted_component") and
    prot.getFile() = critical.getFile()
  ) and
  not GeneratedTrustFacts::hasSuppressor(auth, "correct_component_protected") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth, "TWE-DESIGN-002 (candidate): TEE protects a component but a critical component for the claimed property is unprotected."
