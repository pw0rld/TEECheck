/**
 * @name TEE fetch: Rust call sites
 * @description Repo-wide ENUMERATION of every function/method CALL SITE in
 *              real (non-vendored, non-target) Rust source. Output rows are
 *              passed verbatim to the LLM classifier; this query emits NO
 *              verdicts. Per Decision-R, rust-all 0.2.4 has no qualified-name
 *              or declaring-type API, so calls are identified by NAME +
 *              SIGNATURE + LOCATION only.
 * @kind problem
 * @id web3-tee/trustir-rust/fetch-calls
 * @problem.severity info
 * @tags tee
 *       trustir/fetch
 *       trustir/enumeration
 */
import rust
import common.Fetch

from Call c
where
  not Fetch::excludedFromEnumeration(c.getLocation().getFile())
select c,
  "call_site|" +
  "callee=" + c.getTargetName() + "|" +
  "arg_count=" + count(Expr a | a = c.getAnArgument()).toString() + "|" +
  "file=" + c.getLocation().getFile().getRelativePath() + "|" +
  "line=" + c.getLocation().getStartLine().toString()
