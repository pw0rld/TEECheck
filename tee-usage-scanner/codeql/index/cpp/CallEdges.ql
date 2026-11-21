/**
 * @name Resolved call edges
 * @description One row per call that resolves to exactly one definition in
 *              this tree, with both ends identified by definition.
 *
 *              THREE kinds of call produce no row here, and a consumer must
 *              know all three before reading an absent edge as "never
 *              called". Measured on OP-TEE@a9386bf, of 42,317 call sites:
 *
 *                35,019  callee defined exactly once   -> a row
 *                 3,458  callee has no definition in this tree (memcpy and
 *                        friends): an edge would carry a callee id naming
 *                        no capsule
 *                 2,288  callee defined several times: which definition the
 *                        linker picks is not decidable here, so emitting one
 *                        would be a fabrication and emitting all would claim
 *                        every implementation is called
 *                 1,552  no target at all -> UnresolvedCalls.ql
 *
 *              CallSiteCounts.ql reports the four totals so the gap between
 *              this list and the resolved count is a number, not a mystery.
 * @kind table
 * @id cpp/teecheck-index-call-edges
 *
 * Columns: caller_name, caller_file, caller_line, caller_sig,
 *          callee_name, callee_file, callee_line, callee_sig,
 *          call_file, call_line
 */

import cpp
import Index

from Call c, FunctionDeclarationEntry caller, FunctionDeclarationEntry callee
where
  caller = enclosingDefinition(c) and
  callee = definitionOf(c.getTarget()) and
  count(definitionOf(c.getTarget())) = 1
select caller.getFunction().getName(), caller.getFile().getRelativePath(),
  caller.getLocation().getStartLine(), caller.getFunction().getParameterString(),
  callee.getFunction().getName(), callee.getFile().getRelativePath(),
  callee.getLocation().getStartLine(), callee.getFunction().getParameterString(),
  c.getFile().getRelativePath(), c.getLocation().getStartLine()
