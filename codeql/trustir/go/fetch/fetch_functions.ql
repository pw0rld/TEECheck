/**
 * fetch_functions.ql (Go)
 *
 * Repo-wide enumeration of FUNCTION DEFINITIONS for the IRIS
 * enumerate-then-classify pipeline. One row per declared function or method.
 *
 * Columns:
 *   name       : function / method name (Function.getName())
 *   pkg        : declaring package import path (Package.getPath())
 *   type_name  : receiver type name for methods ("":Function), e.g. "Server"
 *   param_count: number of formal parameters (receiver excluded)
 *   signature  : "pkg.type_name.name(param_count)" summary string
 *   file       : absolute path of the declaration
 *   line       : start line of the declaration
 */

import go
import common.Fetch

from Function f, string name, string pkg, string typeName, int paramCount,
     string typeQualifier, string sig, string file, int line
where
  enumerableFile(f.getLocation().getFile())
  and
  name = f.getName()
  and
  if f instanceof Method
  then (
    typeName = f.(Method).getReceiverType().getName()
    and
    typeQualifier = "." + typeName
    and
    pkg = f.getPackage().getPath()
  )
  else (
    typeName = ""
    and
    typeQualifier = ""
    and
    pkg = f.getPackage().getPath()
  )
  and
  // Formal parameters excluding the method receiver.
  paramCount = count(int i | exists(f.getParameter(i)))
  and
  sig = pkg + typeQualifier + "." + name + "(" + paramCount.toString() + ")"
  and
  file = f.getLocation().getFile().getRelativePath()
  and
  line = f.getLocation().getStartLine()
select f, name, pkg, typeName, paramCount, sig, file, line
