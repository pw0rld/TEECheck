/**
 * Control.qll (JavaScript)
 *
 * Conservative control-flow dominance predicates. Uses the JavaScript BasicBlock
 * dominance API exposed by `import javascript`. Where precise dominance cannot
 * be established cheaply, the predicate conservatively approximates and may
 * over-report `dominates` (favoring false negatives in downstream vulnerability
 * queries, since an over-broad `dominates` suppresses findings).
 *
 * JS API notes:
 *   - `DataFlow::Node.getBasicBlock()` returns a `BasicBlock`.
 *   - `BasicBlock.dominates(BasicBlock)` is reflexive dominance within a CFG.
 *   - The enclosing scope is `DataFlow::Node.getContainer()` (a `StmtContainer`),
 *     used in place of the Go `getEnclosingCallable()` to assert co-locality.
 *
 * Provides module `Control` with:
 *   - dominates(DataFlow::Node a, DataFlow::Node b)
 *   - onFailureBranchBlocks(DataFlow::Node guard, DataFlow::Node auth)
 */

import javascript

module Control {
  /**
   * Holds if data-flow node `a` dominates data-flow node `b` (i.e. every path
   * from the entry of the enclosing container to `b` passes through `a`).
   * Conservative: requires both nodes to live in a reachable basic block of the
   * same container and uses the JavaScript BasicBlock dominance relation.
   */
  predicate dominates(DataFlow::Node a, DataFlow::Node b) {
    exists(ReachableBasicBlock abb, ReachableBasicBlock bbb |
      abb = a.getBasicBlock() and
      bbb = b.getBasicBlock() and
      a.getContainer() = b.getContainer() and
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
    guard.getContainer() = auth.getContainer()
  }
}
