/**
 * fetch_params.ql (Go)
 *
 * Repo-wide enumeration of FUNCTION PARAMETERS for the IRIS
 * enumerate-then-classify pipeline. One row per formal parameter.
 * Method receivers are excluded (ReceiverVariable is a subclass of Parameter
 * in go-all); receiver identity is reported separately by fetch_functions.
 *
 * Columns:
 *   param_name      : parameter name (Parameter.getName())
 *   func_name       : enclosing function name
 *   pkg             : enclosing package import path
 *   type_name       : enclosing receiver type name ("":Function), e.g. "Server"
 *   param_type      : parameter type as written (Type.getName())
 *   param_index     : 0-based position in the parameter list
 *   file            : absolute path of the declaration
 *   line            : start line of the declaration
 */

import go
import common.Fetch

from Parameter p, Function f, int idx, string paramName, string funcName,
     string pkg, string typeName, string paramType, string file, int line
where
  f.getParameter(idx) = p
  and
  // Exclude method receivers (reported via fetch_functions).
  not p instanceof ReceiverVariable
  and
  enumerableFile(p.getLocation().getFile())
  and
  paramName = p.getName()
  and
  funcName = f.getName()
  and
  if f instanceof Method
  then (
    typeName = f.(Method).getReceiverType().getName()
    and
    pkg = f.getPackage().getPath()
  )
  else (
    typeName = ""
    and
    pkg = f.getPackage().getPath()
  )
  and
  paramType = p.getType().getName()
  and
  file = p.getLocation().getFile().getRelativePath()
  and
  line = p.getLocation().getStartLine()
select p, paramName, funcName, pkg, typeName, paramType, idx, file, line
