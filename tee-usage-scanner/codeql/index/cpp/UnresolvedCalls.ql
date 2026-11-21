/**
 * @name Unresolved call sites
 * @description Calls whose target the extractor could not name.
 *
 *              This list is the scope every "no callers found" answer
 *              inherits. A count alone cannot answer "could anything
 *              unresolved reach this function?", so each row carries its
 *              enclosing definition and the call expression: without them a
 *              missing caller stays weak evidence however small the total.
 *
 *              resolution_kind states only what the query can prove. An
 *              ExprCall dispatches through an expression — that IS indirect
 *              dispatch, provable from the call's own shape. Anything else
 *              with no target is "unknown": a macro-expanded call and a call
 *              to an undeclared function are indistinguishable here, and
 *              naming one of them would be a claim about a mechanism the
 *              query never established.
 * @kind table
 * @id cpp/teecheck-index-unresolved-calls
 *
 * Columns: enclosing_name, enclosing_file, enclosing_line, enclosing_sig,
 *          call_file, call_line, expression, resolution_kind
 */

import cpp
import Index

from Call c, FunctionDeclarationEntry enclosing, string kind
where
  not exists(c.getTarget()) and
  enclosing = enclosingDefinition(c) and
  (if c instanceof ExprCall then kind = "indirect" else kind = "unknown")
select enclosing.getFunction().getName(), enclosing.getFile().getRelativePath(),
  enclosing.getLocation().getStartLine(), enclosing.getFunction().getParameterString(),
  c.getFile().getRelativePath(), c.getLocation().getStartLine(), c.toString(), kind
