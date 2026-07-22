/**
 * Control.qll (Rust)
 *
 * Control-flow dominance predicates over DataFlow::Node.
 *
 * rust-all 0.2.4 exposes BasicBlock with a real `dominates(BasicBlock)` relation
 * (generic codeql.controlflow.BasicBlock) and CfgNode.getAstNode(), so precise
 * dominance IS computable here: a DataFlow::Node maps to its enclosing basic
 * block via `bb.getANode().getAstNode() = <expr>`, and `blockA.dominates(blockB)`
 * holds iff every path from the CFG entry to blockB passes through blockA. This
 * is the structural foundation the guard model needs: a guard protects an
 * authority iff the guard's call block dominates the authority's block (within
 * the same enclosing callable — dominance does not hold across CFGs).
 *
 * Provides module `Control` with:
 *   - dominates(DataFlow::Node a, DataFlow::Node b)
 *   - blockOf(DataFlow::Node n)
 *   - callableOf(DataFlow::Node n)
 *   - onFailureBranchBlocks(DataFlow::Node guard, DataFlow::Node auth)
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.controlflow.BasicBlocks

module Control {
  /**
   * Holds if data-flow node `a` dominates data-flow node `b`: every path from
   * the CFG entry to b's basic block passes through a's basic block. Restricted
   * to the same enclosing callable (dominance is per-CFG; cross-function it is
   * false, which is the conservative outcome). This is REAL control-flow
   * dominance, computed by CodeQL — never a name match.
   */
  predicate dominates(DataFlow::Node a, DataFlow::Node b) {
    callableOf(a) = callableOf(b) and
    exists(BasicBlock ba, BasicBlock bb |
      ba = blockOf(a) and bb = blockOf(b) and ba.dominates(bb)
    )
  }

  /**
   * The basic block containing data-flow node `n`'s expression. Binds the block
   * whose CFG nodes include `n`'s AST expression. (Only the expr arm is needed:
   * guard/authority nodes are call-based. The asExpr dispatch mirrors
   * :pred:`callableOf` and is safe against param-typed nodes.)
   */
  BasicBlock blockOf(DataFlow::Node n) {
    exists(Expr e | n.asExpr() = e and result.getANode().getAstNode() = e)
  }

  /**
   * Enclosing callable of a DataFlow node, handling BOTH expr nodes (calls,
   * field reads) and parameter nodes. The public ``DataFlow::Node`` does not
   * expose ``getEnclosingCallable`` (only the internal Node does), so we route
   * expr nodes via ``asExpr().getEnclosingCallable()`` and parameter nodes via
   * ``asParameter().getEnclosingCallable()``. Calling ``.asExpr()`` on a node
   * that is provably a parameter (e.g. an authority SUBJECT bound by a param
   * fact clause) is a compile ERROR ("SourceParameterNode incompatible with
   * TExprNode"); this dispatch avoids that.
   */
  Callable callableOf(DataFlow::Node n) {
    exists(Expr e | n.asExpr() = e and result = e.getEnclosingCallable())
    or
    exists(ParamBase pb | n.asParameter() = pb and result = pb.getEnclosingCallable())
  }

  /**
   * Holds if `auth` lies on a failure branch following `guard`. Conservative:
   * true if guard and auth live in the same enclosing callable but guard does
   * not structurally dominate auth. Uses :predicate:`callableOf` so param-typed
   * guard/auth nodes are handled.
   */
  predicate onFailureBranchBlocks(DataFlow::Node guard, DataFlow::Node auth) {
    not dominates(guard, auth) and
    callableOf(guard) = callableOf(auth)
  }
}
