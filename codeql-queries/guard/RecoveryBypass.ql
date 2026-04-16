/**
 * @name Recovery or migration bypasses attestation checks
 * @description Recovery, migration, or upgrade paths bypass normal
 *              attestation or policy checks.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/guard/recovery-bypass
 * @tags security
 *       tee
 *       guard
 */

import rust

from FnCall path_fn
where
  path_fn.getName().toLowerCase().matches([
    "%recover%", "%restore%", "%migrate%", "%upgrade%",
    "%unseal%", "%rollback%"
  ])
  and not exists(FnCall guard |
    guard.getName().toLowerCase().matches([
      "%attest%", "%verify%", "%validate%", "%check%"
    ])
  )
select path_fn,
  "Recovery or migration path $@ may bypass attestation or policy checks.",
  path_fn, path_fn.getName()
