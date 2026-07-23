/**
 * fetch_calls.ql (JavaScript)
 *
 * Repo-wide enumeration of CALL SITES for the IRIS enumerate-then-classify
 * pipeline. Produces a table of real CallExpr AST nodes — the LLM classifies
 * roles (source / sink / authority / neutral) from this list.
 *
 * Mirrors `../go/fetch/fetch_calls.ql`. This is a plain SELECT query
 * (NOT path-problem): one row per call site.
 *
 * Columns (positional, matching the Go schema consumed by
 * tee_audit.trustir.codeql_fetch):
 *   name       : callee name (MethodCallExpr.getMethodName() / callee Identifier)
 *   pkg        : "" (JS has no static package import path; resolver grounds later)
 *   type_name  : "" (JS receiver types are dynamic; resolver grounds separately)
 *   arg_count  : number of arguments at the call site
 *   signature  : "<name>(<arg_count>)" summary string
 *   file       : absolute path of the call site
 *   line       : start line of the call site
 */

import javascript
import common.Fetch

from CallExpr c, string name, string pkg, string typeName,
     int argCount, string sig, string file, int line
where
  enumerableLocation(c)
  and
  // Resolve the callee name. Method calls (`x.f()`) report the method name;
  // plain identifier callees (`f()`) report the identifier name. Calls whose
  // callee cannot be resolved to a name are skipped (rare; usually dynamic).
  if c instanceof MethodCallExpr
  then name = c.(MethodCallExpr).getMethodName()
  else if c.getCallee().(Identifier).getName() = c.getCallee().(Identifier).getName()
  then name = c.getCallee().(Identifier).getName()
  else name = ""
  and
  name != ""
  and
  // JS has no Go-style package import path / receiver type tuple; emit "" so
  // the column count matches the Go schema and the resolver grounds identity.
  pkg = ""
  and
  typeName = ""
  and
  argCount = count(int i | exists(c.getArgument(i)))
  and
  sig = name + "(" + argCount.toString() + ")"
  and
  file = c.getLocation().getFile().getRelativePath()
  and
  line = c.getLocation().getStartLine()
select c, name, pkg, typeName, argCount, sig, file, line
