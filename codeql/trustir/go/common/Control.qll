/**
 * Control.qll (Go)
 *
 * Conservative control-flow dominance predicates. Uses the Go BasicBlock /
 * ReachableBasicBlock API. Where precise dominance cannot be established cheaply,
 * the predicate conservatively approximates and may over-report `dominates`
 * (favoring false negatives in downstream vulnerability queries, since an
 * over-broad `dominates` suppresses findings).
 *
 * Provides module `Control` with:
 *   - dominates(DataFlow::Node a, DataFlow::Node b)
 *   - onFailureBranchBlocks(DataFlow::Node guard, DataFlow::Node auth)
 */

import go

module Control {
  /**
   * Holds if data-flow node `a` dominates data-flow node `b` (i.e. every path
   * from the entry of the enclosing callable to `b` passes through `a`).
   * Conservative: requires both nodes to live in a reachable basic block of the
   * same callable and uses the Go BasicBlock dominance relation.
   */
  predicate dominates(DataFlow::Node a, DataFlow::Node b) {
    exists(ReachableBasicBlock abb, ReachableBasicBlock bbb |
      abb = a.getBasicBlock() and
      bbb = b.getBasicBlock() and
      a.getEnclosingCallable() = b.getEnclosingCallable() and
      abb.dominates(bbb)
    )
  }

  /**
   * Holds if `auth` lies on a failure branch following `guard`. Conservative:
   * true if the guard's basic block does not dominate the authority's basic
   * block (i.e. there is a path that bypasses the guard) — i.e. the authority
   * is reachable without passing the guard's success edge.
   */
  predicate onFailureBranchBlocks(DataFlow::Node guard, DataFlow::Node auth) {
    not dominates(guard, auth) and
    guard.getEnclosingCallable() = auth.getEnclosingCallable()
  }
}
