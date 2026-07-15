/**
 * TypeBarriers.qll (Go)
 *
 * DETERMINISTIC, LLM-FREE content-reduction barriers. A tainted secret whose
 * content is reduced to a non-carrying scalar (e.g. len(secret), cap(slice)) no
 * longer carries the secret CONTENT — only an unrelated magnitude. Treating
 * those call results as taint barriers suppresses spurious "secret reached a
 * log/decision" paths where only the length (not the content) flows onward.
 *
 * Intentionally NARROW (len/cap only) to avoid over-suppression that would hide
 * real secret->sink paths. If the iteration-3 real-path validation (US-010)
 * shows recall regressions, narrow further or empty this predicate. Honors the
 * core principle: human-authored, LLM-free, auditable.
 *
 * Provides module `TypeBarriers` with isBasicTypeBarrier(DataFlow::Node n).
 */

import go

module TypeBarriers {
  /**
   * Holds when n is a call to a content-reducing builtin (len, cap): the result
   * is a magnitude unrelated to the secret's content, so content taint must not
   * propagate through it.
   */
  predicate isBasicTypeBarrier(DataFlow::Node n) {
    exists(DataFlow::CallNode c |
      c.getTarget().getName() in ["len", "cap"]
      and n = c
    )
  }
}
