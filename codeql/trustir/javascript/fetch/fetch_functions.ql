/**
 * fetch_functions.ql (JavaScript)
 *
 * Repo-wide enumeration of FUNCTION DEFINITIONS for the IRIS
 * enumerate-then-classify pipeline. One row per declared function, method, or
 * arrow function with a resolvable name.
 *
 * Mirrors `../go/fetch/fetch_functions.ql`. Plain SELECT query.
 *
 * Columns (positional, matching the Go schema):
 *   name        : function name (Function.getName())
 *   pkg         : "" (JS has no static package import path)
 *   type_name   : "" (JS receiver / declaring class reported separately by TWE)
 *   param_count : number of formal parameters
 *   signature   : "<name>(<param_count>)" summary string
 *   file        : absolute path of the declaration
 *   line        : start line of the declaration
 */

import javascript
import common.Fetch

from Function f, string name, string pkg, string typeName, int paramCount,
     string sig, string file, int line
where
  enumerableFile(f.getLocation().getFile())
  and
  name = f.getName()
  and
  name != ""
  and
  pkg = ""
  and
  typeName = ""
  and
  paramCount = f.getNumParameter()
  and
  sig = name + "(" + paramCount.toString() + ")"
  and
  file = f.getLocation().getFile().getRelativePath()
  and
  line = f.getLocation().getStartLine()
select f, name, pkg, typeName, paramCount, sig, file, line
