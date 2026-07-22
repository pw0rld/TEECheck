/**
 * @name TEE fetch: Rust function definitions
 * @description Repo-wide ENUMERATION of every FUNCTION DEFINITION in real
 *              (non-vendored, non-target) Rust source. Emits the function NAME,
 *              its param arity (param_count — the resolver's RELIABLE Rust match
 *              key, since the LLM can echo an arity but not a full type string),
 *              and a real param-type signature (sig — built via
 *              Param.getTypeRepr().toAbbreviatedString() because rust-all 0.2.4
 *              exposes no monolithic signature accessor). sig is for human
 *              inspection / disambiguation only; the resolver matches on arity.
 *              Output rows are passed verbatim to the LLM classifier; this query
 *              emits NO verdicts.
 * @kind problem
 * @id web3-tee/trustir-rust/fetch-functions
 * @problem.severity info
 * @tags tee
 *       trustir/fetch
 *       trustir/enumeration
 */
import rust
import common.Fetch

from Function f
where
  f.hasName() and
  not Fetch::excludedFromEnumeration(f.getLocation().getFile())
select f,
  "function_def|" +
  "name=" + f.getName().getText() + "|" +
  "param_count=" + f.getParamList().getNumberOfParams().toString() + "|" +
  "sig=" + fnSignature(f) + "|" +
  "file=" + f.getLocation().getFile().getRelativePath() + "|" +
  "line=" + f.getLocation().getStartLine().toString()

/** Real param-type signature "name(t1, t2, ...)" from abbreviated type reprs.
 *  rust-all 0.2.4 has no monolithic signature accessor, so types come from each
 *  Param's TypeRepr. Abbreviated reprs may contain "..." (elided generics), so
 *  this is an inspection/disambiguation aid, NOT an exact match key — the
 *  resolver matches on arity (param_count) for reliability. */
string fnSignature(Function f) {
  result = f.getName().getText() + "(" +
    concat(string t |
      exists(Param p |
        p = f.getParamList().getAParamBase() and
        t = p.getTypeRepr().toAbbreviatedString()) |
      t, ", ") + ")"
}
