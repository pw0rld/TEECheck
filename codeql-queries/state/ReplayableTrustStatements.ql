/**
 * @name Replayable trust statements
 * @description Replayable trust statements or stale authorization artifacts
 *              can be reused across sessions or restarts.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/state/replayable-trust-statements
 * @tags security
 *       tee
 *       state
 */

import rust

from FnCall trust_fn
where
  trust_fn.getName().toLowerCase().matches([
    "%accept_token%", "%accept_ticket%", "%accept_certificate%",
    "%accept_authorization%", "%grant_access%"
  ])
  and not exists(PathExpr freshness |
    freshness.getTarget().getName().toLowerCase().matches([
      "%timestamp%", "%nonce%", "%challenge%", "%session_id%",
      "%expiry%", "%ttl%"
    ])
    and trust_fn.getAnArgument().getAChild*() = freshness
  )
select trust_fn,
  "Trust statement acceptance $@ may lack replay protection (no timestamp, nonce, or session binding).",
  trust_fn, trust_fn.getName()
