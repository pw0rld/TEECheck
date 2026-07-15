/**
 * GeneratedTrustFacts.qll (Rust)
 *
 * GENERATED from resolved TrustIR by the Python fact generator. FACTS ONLY — no
 * vulnerability logic. Each predicate is populated with resolved (file, line)
 * locations of TrustIR claim fields, authority points, subjects, sources, sinks.
 *
 * The default (empty) body below is the interface contract; the generator
 * appends clauses per resolved fact at validation time.
 */
import rust
import codeql.rust.dataflow.DataFlow

module GeneratedTrustFacts {
  /**
   * A data-flow node that carries a claim field with the given semantic role
   * (e.g. "attested_public_key", "report_data", "tcb_status").
   */
  predicate isClaimField(DataFlow::Node n, string role) { none() }

  /** A call/expr node that is an authority point of the given kind. */
  predicate isAuthorityPoint(DataFlow::Node n, string kind) { none() }

  /** The authority-subject expression for a given authority-subject role. */
  predicate isAuthoritySubject(DataFlow::Node n, string role) { none() }

  /** A trust source of the given role (host input, OCALL return, env, ...). */
  predicate isTrustSource(DataFlow::Node n, string role) { none() }

  /** A trust sink of the given role (key derivation input, policy decision, ...). */
  predicate isTrustSink(DataFlow::Node n, string role) { none() }

  /** A suppressor holds at node n (e.g. "checked_inside_verifier", "test_only"). */
  predicate hasSuppressor(DataFlow::Node n, string suppressor) { none() }

  /**
   * A guard function of the given catalog guard_kind (identity by name). Its
   * protection of an authority is verified STRUCTURALLY by Guards.qll (CFG
   * dominance) — this predicate only records WHICH functions are guards, never
   * whether a guard protects a given authority.
   */
  predicate isGuardFunction(Function f, string kind) { none() }

  /** An extra taint-flow step introduced by TrustIR modeling. */
  predicate isAdditionalTrustFlowStep(DataFlow::Node pred, DataFlow::Node succ) { none() }

  /** Associate an authority point node with its subject node. */
  predicate authoritySubjectOf(DataFlow::Node auth, DataFlow::Node subject) { none() }
}
