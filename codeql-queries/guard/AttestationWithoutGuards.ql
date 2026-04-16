/**
 * @name Attestation acceptance without required guards
 * @description Attestation acceptance reaches validator admission, peer acceptance,
 *              or key release without all required guards being verified.
 * @kind problem
 * @problem.severity error
 * @id tee-audit/guard/attestation-without-guards
 * @tags security
 *       tee
 *       guard
 */

import rust

from FnCall accept, PathExpr target
where
  accept.getName().toLowerCase().matches([
    "%accept_attestation%", "%accept_report%", "%accept_quote%",
    "%admit%", "%verify_report%"
  ])
  and target.getTarget().getName().toLowerCase().matches([
    "%admit%", "%release%", "%peer_accept%"
  ])
  and not exists(FnCall guard |
    guard.getName().toLowerCase().matches([
      "%verify_signature%", "%check_revocation%", "%validate_tcb%",
      "%check_debug%", "%verify_quote%"
    ])
  )
select accept,
  "Attestation acceptance at $@ may proceed without all required guard checks.",
  target, target.toString()
