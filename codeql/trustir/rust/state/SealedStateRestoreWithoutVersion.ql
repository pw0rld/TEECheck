/**
 * @name TWE-STATE-001: Sealed state restored without version or epoch continuity
 * @description Persisted TEE state is restored without verifying a version /
 *              epoch / monotonic-counter / state-root continuity guard, allowing
 *              rollback of protected state. State-object kinds are catalog enum
 *              values (state_object_kind); the restore authority kind is
 *              state_restore_acceptance (authority_kind).
 * @kind problem
 * @id web3-tee/trustir-rust/twe-state-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-state-001
 */
import rust
import codeql.rust.dataflow.DataFlow
import common.GeneratedTrustFacts
import common.TestScope

from DataFlow::Node stateObject, DataFlow::Node auth, string stateKind
where
  isStateObject(stateObject, stateKind) and
  GeneratedTrustFacts::isAuthorityPoint(auth, "state_restore_acceptance") and
  not hasContinuityGuard(auth, stateKind) and
  not GeneratedTrustFacts::hasSuppressor(auth, "continuity_check_safe") and
  not GeneratedTrustFacts::hasSuppressor(stateObject, "continuity_check_safe") and
  not TestScope::isTestOnlyPath(auth) and
  not TestScope::isExampleOnlyPath(auth)
select auth,
  "TWE-STATE-001: sealed state restored without version/epoch continuity check (@@).",
  stateObject, stateKind + " restored without continuity guard."

/** Restorable state objects (state_object_kind enum values). */
predicate isStateObject(DataFlow::Node n, string kind) {
  kind = "sealed_blob" and GeneratedTrustFacts::isClaimField(n, "sealed_blob")
  or
  kind = "checkpoint" and GeneratedTrustFacts::isClaimField(n, "checkpoint")
  or
  kind = "runtime_state_root" and GeneratedTrustFacts::isClaimField(n, "runtime_state_root")
  or
  kind = "key_rotation_state" and GeneratedTrustFacts::isClaimField(n, "key_rotation_state")
  or
  kind = "committee_membership_state" and
  GeneratedTrustFacts::isClaimField(n, "committee_membership_state")
}

/**
 * Holds when auth carries a continuity guard appropriate for the restored state
 * object. Continuity guards are recorded as free-form suppressors by the fact
 * generator (no dedicated enum); each guard is treated as covering every
 * restorable state-object kind, so stateKind is bound via isStateObject.
 */
predicate hasContinuityGuard(DataFlow::Node auth, string stateKind) {
  isStateObjectKind(stateKind) and
  (
    GeneratedTrustFacts::hasSuppressor(auth, "monotonic_counter_check")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "version_check")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "epoch_check")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "state_root_check")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "migration_version_check")
    or
    GeneratedTrustFacts::hasSuppressor(auth, "continuity_check")
  )
}

/** Recognized state_object_kind enum values. */
predicate isStateObjectKind(string kind) {
  kind = "sealed_blob"
  or
  kind = "checkpoint"
  or
  kind = "runtime_state_root"
  or
  kind = "key_rotation_state"
  or
  kind = "committee_membership_state"
}
