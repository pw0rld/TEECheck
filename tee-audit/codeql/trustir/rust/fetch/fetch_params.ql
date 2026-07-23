/**
 * @name TEE fetch: Rust function parameters
 * @description Repo-wide ENUMERATION of every function PARAMETER in real
 *              (non-vendored, non-target) Rust source. Parameter names are
 *              recovered via the chain Function -> getParamList().getAParamBase()
 *              -> (cast Param) -> getPat() -> IdentPat -> getName().getText().
 *              Parameters whose pattern is not an IdentPat (e.g. tuple / wildcard
 *              patterns) are emitted with name="<non-ident-pat>" so the LLM still
 *              sees their type and location. Output rows are passed verbatim to
 *              the LLM classifier; this query emits NO verdicts.
 * @kind problem
 * @id web3-tee/trustir-rust/fetch-params
 * @problem.severity info
 * @tags tee
 *       trustir/fetch
 *       trustir/enumeration
 */
import rust
import common.Fetch

from ParamBase pb, Function enclosing
where
  enclosing.getParamList().getAParamBase() = pb and
  not Fetch::excludedFromEnumeration(pb.getLocation().getFile())
select pb,
  "param|" +
  "name=" + paramName(pb) + "|" +
  "enclosing_fn=" + enclosing.getName().getText() + "|" +
  "file=" + pb.getLocation().getFile().getRelativePath() + "|" +
  "line=" + pb.getLocation().getStartLine().toString()

/** Best-effort parameter name: IdentPat binding if present, otherwise a marker.
 *  `ParamBase` is the union of `Param` and `SelfParam`; only `Param` carries a
 *  pattern, so we cast `pb` down to `Param` before reading `getPat()`.
 */
string paramName(ParamBase pb) {
  pb.(Param).getPat().(IdentPat).getName().getText() = result
  or
  not exists(IdentPat ip | ip = pb.(Param).getPat().(IdentPat)) and
  result = "<non-ident-pat>"
}
