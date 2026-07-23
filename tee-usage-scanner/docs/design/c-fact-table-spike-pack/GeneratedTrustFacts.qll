/**
 * GeneratedTrustFacts.qll (C/C++) — SPIKE, hand-populated.
 *
 * Mirrors tee-audit's Rust fact table: FACTS ONLY, no vulnerability logic.
 * In production these clauses are emitted by the fact generator from
 * LLM-annotated, resolver-verified TrustIR. Here they are filled by hand with
 * the real OP-TEE entities, to test whether a thin-shell query consuming this
 * table can express the CVE-2026-44362 gap on C.
 */
import cpp

module GeneratedTrustFacts {
  /** A function that produces a pub-key struct whose fields feed authority. */
  predicate isClaimProducer(Function f, string role) {
    f.getName() = "shdr_load_pub_key" and role = "signed_subkey_pubkey"
  }

  /** The rollback-relevant field the producer must propagate into its output. */
  predicate rollbackVersionField(string field) { field = "version" }

  /** The struct type the producer fills through its output-pointer param. */
  predicate producedStruct(string typeName) { typeName = "shdr_pub_key" }

  /** An authority point: a call that consumes a version for a rollback check. */
  predicate isRollbackAuthority(FunctionCall c, string kind) {
    c.getTarget().getName() = "check_update_version" and
    kind = "subkey_version_rollback_check"
  }
}
