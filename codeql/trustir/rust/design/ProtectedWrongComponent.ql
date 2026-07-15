/**
 * @name TWE-DESIGN-002: TEE protects the wrong component for the claimed property
 * @description Structural candidate: the architecture protects a component that
 *              is not on the critical trust path for the claimed asset — i.e. a
 *              secret/asset sink is reached by an authority whose attested
 *              subject lies in a different component/file than the sink, so the
 *              TEE protection does not actually cover the asset. Design queries
 *              have no dedicated enum, so we approximate using authority_kind,
 *              observable_sink_role trust sinks, and authoritySubjectOf joins.
 *              Reported as a design_candidate.
 * @kind problem
 * @id web3-tee/trustir-rust/twe-design-002
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-design-002
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.TestScope

from DataFlow::Node auth, DataFlow::Node attestedSubject, DataFlow::Node protectedSink
where
  isProductionRelevantAuthority(auth) and
  GeneratedTrustFacts::authoritySubjectOf(auth, attestedSubject) and
  exists(string sinkRole |
    GeneratedTrustFacts::isTrustSink(protectedSink, sinkRole) and
    isObservableSinkRole(sinkRole)
  ) and
  // The protected sink is in a different file than the attested subject, i.e. the
  // TEE-protected component is not the one carrying the observable asset.
  protectedSink.getLocation().getFile() != attestedSubject.getLocation().getFile() and
  not GeneratedTrustFacts::hasSuppressor(auth, "correct_component_protected") and
  not GeneratedTrustFacts::hasSuppressor(auth, "design_002_resolved") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-DESIGN-002 (candidate): TEE protects a component other than the one carrying the asset (@@).",
  protectedSink, "observable sink not covered by the attested subject's component.",
  attestedSubject, "attested subject protecting a different component."

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

/** Observable sink roles (observable_sink_role enum) that carry a protected asset. */
predicate isObservableSinkRole(string role) {
  role = "host_filesystem_write"
  or
  role = "http_response_body"
  or
  role = "rpc_error_message"
  or
  role = "grpc_status_detail"
  or
  role = "event_emission"
  or
  role = "log_output"
}
