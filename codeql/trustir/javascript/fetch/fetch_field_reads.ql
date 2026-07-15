/**
 * fetch_field_reads.ql (JavaScript)
 *
 * Repo-wide enumeration of PROPERTY READS (DotExpr member accesses) for the
 * IRIS enumerate-then-classify pipeline. One row per `expr.prop` dot access
 * that reads a named property.
 *
 * Mirrors `../go/fetch/fetch_field_reads.ql`. Plain SELECT query.
 *
 * We enumerate DotExpr nodes (the JS AST for `base.prop`) and report the
 * property name plus the enclosing function. IndexExpr (`a[i]`) reads are
 * excluded: their property name is dynamic and not a stable identity.
 *
 * Columns (positional, matching the Go schema):
 *   field_name : property name (DotExpr.getPropertyName())
 *   base_type  : "" (JS base types are dynamic; resolver grounds separately)
 *   func_name  : enclosing function name ("" if at top level)
 *   pkg        : "" (JS has no static package import path)
 *   file       : absolute path of the access
 *   line       : start line of the access
 */

import javascript
import common.Fetch

from DotExpr d, string fieldName, string baseType, string funcName,
     string pkg, string file, int line
where
  enumerableLocation(d)
  and
  fieldName = d.getPropertyName()
  and
  fieldName != ""
  and
  baseType = ""
  and
  if exists(d.getEnclosingFunction())
  then funcName = d.getEnclosingFunction().getName()
  else funcName = ""
  and
  pkg = ""
  and
  file = d.getLocation().getFile().getRelativePath()
  and
  line = d.getLocation().getStartLine()
select d, fieldName, baseType, funcName, pkg, file, line
