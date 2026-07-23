/**
 * @name TEE fetch: Rust field reads
 * @description Repo-wide ENUMERATION of every FIELD READ (field-access
 *              expression `x.field`) in real (non-vendored, non-target) Rust
 *              source. rust-all 0.2.4 exposes field reads via `FieldExpr`
 *              (`x.field` AST node); the field name is `getIdentifier().getText()`
 *              (a NameRef). The enclosing callable is recovered via
 *              `getEnclosingCallable()` on the underlying Expr. Output rows are
 *              passed verbatim to the LLM classifier; this query emits NO verdicts.
 * @kind problem
 * @id web3-tee/trustir-rust/fetch-field-reads
 * @problem.severity info
 * @tags tee
 *       trustir/fetch
 *       trustir/enumeration
 */
import rust
import common.Fetch

from FieldExpr fe
where
  fe.hasIdentifier() and
  not Fetch::excludedFromEnumeration(fe.getLocation().getFile())
select fe,
  "field_read|" +
  "field=" + fe.getIdentifier().getText() + "|" +
  "enclosing_fn=" + enclosingFnName(fe) + "|" +
  "file=" + fe.getLocation().getFile().getRelativePath() + "|" +
  "line=" + fe.getLocation().getStartLine().toString()

/** Name of the callable enclosing `fe`, or "<none>" when not inside a function. */
string enclosingFnName(FieldExpr fe) {
  exists(Function f | f = fe.getEnclosingCallable() | result = f.getName().getText())
  or
  not exists(Function f | f = fe.getEnclosingCallable()) and
  result = "<none>"
}
