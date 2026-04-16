/**
 * @name Partial measurement or identity check
 * @description Measurement, signer, PCR, or version fields are only partially
 *              checked before trusted admission.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/binding/partial-measurement-check
 * @tags security
 *       tee
 *       binding
 */

import rust

from Expr check
where
  // Find comparison expressions involving identity fields
  exists(PathExpr target |
    target.getTarget().getName().toLowerCase().matches([
      "%mrenclave%", "%mrsigner%", "%pcr%", "%mr_signer%",
      "%mr_enclave%", "%measurement%", "%isv_prod_id%",
      "%isv_svn%", "%version%"
    ])
    and check.getAChild*() = target
  )
  and not exists(PathExpr full_target |
    full_target.getTarget().getName().toLowerCase().matches([
      "%mrenclave%", "%mrsigner%", "%measurement%"
    ])
    and check.getAChild*() = full_target
  )
select check,
  "Measurement or identity field check at $@ may be partial.",
  check, check.toString()
