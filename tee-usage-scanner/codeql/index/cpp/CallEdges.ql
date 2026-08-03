/**
 * @name Resolved call edges
 * @description One row per call whose target the extractor could name, with
 *              both ends identified by definition rather than by name.
 *
 *              A call the extractor could not resolve is NOT here — it is in
 *              UnresolvedCalls.ql. Reading an absent edge as "this function
 *              is never called" is only safe once that other list has been
 *              consulted.
 * @kind table
 * @id teecheck/index/call-edges
 *
 * Columns: caller_name, caller_file, caller_line, caller_sig,
 *          callee_name, callee_file, callee_line, callee_sig,
 *          call_file, call_line
 */

import cpp

from Call c, Function caller, Function callee
where
  caller = c.getEnclosingFunction() and
  callee = c.getTarget() and
  callee.hasDefinition() and
  exists(caller.getFile().getRelativePath()) and
  exists(callee.getFile().getRelativePath())
select caller.getName(), caller.getFile().getRelativePath(),
  caller.getLocation().getStartLine(), caller.getParameterString(),
  callee.getName(), callee.getFile().getRelativePath(),
  callee.getLocation().getStartLine(), callee.getParameterString(),
  c.getFile().getRelativePath(), c.getLocation().getStartLine()
