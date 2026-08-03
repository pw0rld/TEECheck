/**
 * @name Unresolved call sites
 * @description Calls whose target the extractor could not name — dispatch
 *              through a function pointer, and anything else with no
 *              statically known callee.
 *
 *              This list is the scope every "no callers found" answer
 *              inherits. A count alone cannot answer "could anything
 *              unresolved reach this function?", so each row carries its
 *              enclosing function and the call expression: without them a
 *              missing caller stays weak evidence however small the total.
 * @kind table
 * @id teecheck/index/unresolved-calls
 *
 * Columns: enclosing_name, enclosing_file, enclosing_line, enclosing_sig,
 *          call_file, call_line, expression, resolution_kind
 */

import cpp

from Call c, Function enclosing
where
  enclosing = c.getEnclosingFunction() and
  not exists(c.getTarget()) and
  exists(c.getFile().getRelativePath())
select enclosing.getName(), enclosing.getFile().getRelativePath(),
  enclosing.getLocation().getStartLine(), enclosing.getParameterString(),
  c.getFile().getRelativePath(), c.getLocation().getStartLine(),
  c.toString(), "indirect"
