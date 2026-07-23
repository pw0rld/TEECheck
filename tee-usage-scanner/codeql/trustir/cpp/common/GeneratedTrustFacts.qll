/**
 * GeneratedTrustFacts.qll (C/C++)
 *
 * GENERATED from resolved TrustIR by the fact generator — FACTS ONLY, never
 * vulnerability logic. Each predicate binds a semantic role/kind (a value
 * from knowledge/twe/definitions/enum_registry.yml) to a real C/C++ entity:
 * the function that produces a claim-bearing value, the field that carries
 * it, the call that authorizes on it. Consuming (thin-shell) queries never
 * anchor on exact line numbers — see §23.4.1 — they key on this identity and
 * let CodeQL resolve the real AST node itself, so a line shift in the target
 * source does not break the query.
 *
 * The default (`none()`) body below is the interface contract every
 * thin-shell query in this pack compiles against, mirroring
 * codeql/trustir/rust/common/GeneratedTrustFacts.qll's shape. This checked-in
 * copy is never mutated in place: internal/trustirfacts (Go) materializes a
 * per-run COPY of this whole query pack with this file's predicate bodies
 * rewritten to the facts for the case under analysis (see
 * internal/trustirfacts/facttable.go and querypack.go). The first slice
 * populates those facts DETERMINISTICALLY from a small hand-authored
 * registry, not from an LLM annotation pipeline — that pipeline is deferred
 * past this skeleton (docs/TEECHECK_TEE_AUDIT_MERGE.zh-CN.md §23.2/§23.3).
 *
 * role/kind string values come from exactly one vocabulary —
 * knowledge/twe/definitions/enum_registry.yml — shared with the (future)
 * annotation prompt. This file must never redeclare or hardcode a second
 * copy of that list; see §23.4.2 on why a second definition site was the
 * fatal v1 bug this constraint exists to prevent.
 */
import cpp

module GeneratedTrustFacts {
  /**
   * A function that produces a claim-bearing value consumed by a downstream
   * authority. `role` is a claim_field_role enum value (e.g.
   * "security_version").
   */
  predicate isClaimProducer(Function f, string role) { none() }

  /**
   * The rollback-relevant field name the producer must propagate into its
   * output struct for the authority's check to be meaningful.
   */
  predicate rollbackVersionField(string field) { none() }

  /** The struct type the producer fills through its output-pointer param. */
  predicate producedStruct(string typeName) { none() }

  /**
   * An authority point: a call that consumes a version/state field for a
   * rollback decision. `kind` is an authority_kind enum value (e.g.
   * "state_restore_acceptance").
   */
  predicate isRollbackAuthority(FunctionCall c, string kind) { none() }

  /**
   * A suppressor recorded against a producer or authority function (e.g.
   * "test_only", "version_propagated_elsewhere"). Declared for interface
   * parity with the other language packs (codeql/trustir/rust) and for
   * future suppressor support; the STATE/rollback thin shell in this first
   * slice does not consume it yet — see §23.2's deferred-annotation note.
   * Always `none()` until the annotation pipeline lands.
   */
  predicate hasSuppressor(Function f, string suppressor) { none() }
}
