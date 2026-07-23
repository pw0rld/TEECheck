/**
 * Bindings.qll (Go) — iteration 2.
 *
 * hasAcceptedBindingRelation means the claim is cryptographically/semantically
 * BOUND to the subject (e.g. the attested public key equals/derives the
 * registered agent address). This is NOT the same as authoritySubjectOf (which
 * only says the subject belongs to the authority). v1 conflated the two and so
 * suppressed every BIND-001 finding.
 *
 * Conservative: a binding is accepted only when an explicit, modeled binding
 * edge exists (from a BINDING annotation). With no such edge, the pair is
 * considered UNBOUND -> the binding query flags it.
 */
import go
import common.GeneratedTrustFacts

module Bindings {
  predicate hasAcceptedBindingRelation(DataFlow::Node claim, DataFlow::Node subject, DataFlow::Node auth) {
    // Explicit modeled binding edges can be emitted into GeneratedTrustFacts
    // (bindingEdge) in future refinement. None by default => unbound => flagged.
    none()
  }
}
