/**
 * fetch_params.ql (JavaScript)
 *
 * Repo-wide enumeration of FUNCTION PARAMETERS for the IRIS
 * enumerate-then-classify pipeline. One row per formal parameter with a
 * resolvable name.
 *
 * Mirrors `../go/fetch/fetch_params.ql`. Plain SELECT query.
 *
 * Columns (positional, matching the Go schema):
 *   param_name  : parameter name (Parameter.getName() via a bound Variable)
 *   func_name   : enclosing function name (Function.getName())
 *   pkg         : "" (JS has no static package import path)
 *   type_name   : "" (JS receiver / declaring class reported separately)
 *   param_type  : parameter type as written (TypeAnnotation), "" if untyped
 *   param_index : 0-based position in the parameter list (Parameter.getIndex())
 *   file        : absolute path of the declaration
 *   line        : start line of the declaration
 */

import javascript
import common.Fetch

from Parameter p, Function f, string paramName, string funcName,
     string pkg, string typeName, string paramType, int idx, string file, int line
where
  p.getParent() = f
  and
  enumerableFile(p.getLocation().getFile())
  and
  exists(Variable v | v = p.getAVariable() and paramName = v.getName())
  and
  paramName != ""
  and
  funcName = f.getName()
  and
  pkg = ""
  and
  typeName = ""
  and
  if exists(p.getTypeAnnotation())
  then paramType = p.getTypeAnnotation().toString()
  else paramType = ""
  and
  idx = p.getIndex()
  and
  file = p.getLocation().getFile().getRelativePath()
  and
  line = p.getLocation().getStartLine()
select p, paramName, funcName, pkg, typeName, paramType, idx, file, line
