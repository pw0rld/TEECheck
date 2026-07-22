/**
 * fetch_field_reads.ql (Go)
 *
 * Repo-wide enumeration of FIELD READS (SelectorExpr member accesses) for the
 * IRIS enumerate-then-classify pipeline. One row per `x.field` selection that
 * refers to a struct field.
 *
 * We enumerate SelectorExpr nodes (the Go AST for `base.selector`) and report
 * the selector name plus the static type of the base expression, which is the
 * authoritative identity of the field-holding type for the LLM to classify.
 *
 * Scope: only selections whose base expression has a struct type (after
 * pointer-dereference). This excludes package-qualified selectors (`pkg.Con`)
 * and map/slice element accesses, which are not field reads, and keeps the
 * result set within CodeQL's evaluation limit on large repos.
 *
 * Columns:
 *   field_name : selector identifier (getSelector().getName())
 *   base_type  : static type name of the base expr (Type.getName())
 *   func_name  : enclosing function name ("":Function.getName() if unbound)
 *   pkg        : enclosing function package import path ("":Function.getName() if unbound)
 *   file       : absolute path of the access
 *   line       : start line of the access
 */

import go
import common.Fetch

from SelectorExpr sel, string fieldName, string baseType, string funcName,
     string pkg, string file, int line
where
  enumerableLocation(sel)
  and
  fieldName = sel.getSelector().getName()
  and
  // Restrict to genuine field reads: the base expression's type (after
  // peeling pointer indirection) must be a struct type. This excludes
  // package-qualified selectors and map/slice element accesses.
  sel.getBase().getType().getUnderlyingType() instanceof StructType
  and
  // Static type of the base expression — the field-holding type.
  baseType = sel.getBase().getType().getName()
  and
  // Enclosing function declaration, if any (package-level initializers have none).
  if exists(FuncDecl fd | fd = sel.getEnclosingFunction())
  then (
    funcName = sel.getEnclosingFunction().getName()
    and
    if exists(sel.getEnclosingFunction().(MethodDecl).getReceiverType())
    then pkg = sel.getEnclosingFunction().(MethodDecl).getReceiverType().getPackage().getPath()
    else pkg = sel.getEnclosingFunction().getFile().getPackageName()
  )
  else (
    funcName = ""
    and
    pkg = ""
  )
  and
  file = sel.getLocation().getFile().getRelativePath()
  and
  line = sel.getLocation().getStartLine()
select sel, fieldName, baseType, funcName, pkg, file, line
