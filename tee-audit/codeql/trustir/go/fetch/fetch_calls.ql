/**
 * fetch_calls.ql (Go)
 *
 * Repo-wide enumeration of CALL SITES for the IRIS enumerate-then-classify
 * pipeline. Produces a table of real CallExpr AST nodes — the LLM classifies
 * roles (source / sink / authority / neutral) from this list.
 *
 * This is a plain SELECT query (NOT path-problem): one row per call site.
 *
 * Columns:
 *   name       : callee getName()                    e.g. "Open" / "HasPrefix"
 *   pkg        : callee declaring package import path (Package.getPath())
 *   type_name  : receiver type name for methods ("":Function), e.g. "os.File"
 *   arg_count  : number of arguments at the call site
 *   signature  : "pkg.name(arg_count)" summary string
 *   file       : absolute path of the call site
 *   line       : start line of the call site
 */

import go
import common.Fetch

from CallExpr c, Function callee, string name, string pkg, string typeName,
     int argCount, string sig, string file, int line
where
  callee = c.getTarget()
  and
  enumerableLocation(c)
  and
  name = callee.getName()
  and
  // Package import path; for methods this is the receiver type's package
  // (Method.getPackage() already routes through getReceiverType().getPackage()).
  if callee instanceof Method
  then (
    typeName = callee.(Method).getReceiverType().getName()
    and
    pkg = callee.getPackage().getPath()
  )
  else (
    typeName = ""
    and
    pkg = callee.getPackage().getPath()
  )
  and
  argCount = count(int i | exists(c.getArgument(i)))
  and
  sig = pkg + "." + name + "(" + argCount.toString() + ")"
  and
  file = c.getLocation().getFile().getRelativePath()
  and
  line = c.getLocation().getStartLine()
select c, name, pkg, typeName, argCount, sig, file, line
