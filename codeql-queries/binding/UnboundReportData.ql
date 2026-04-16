/**
 * @name Report data not bound to attested key
 * @description Report data does not bind the attested key, challenge,
 *              or output to the verified evidence.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/binding/unbound-report-data
 * @tags security
 *       tee
 *       binding
 */

import rust

from FnCall report_fn
where
  report_fn.getName().toLowerCase().matches([
    "%report%", "%attest%", "%get_quote%", "%get_evidence%"
  ])
  and not exists(PathExpr binding_field |
    binding_field.getTarget().getName().toLowerCase().matches([
      "%report_data%", "%user_data%", "%challenge%", "%nonce%",
      "%public_key%", "%bind%"
    ])
    and report_fn.getAnArgument().getAChild*() = binding_field
  )
select report_fn,
  "Report generation $@ may not bind output to the attested key or challenge.",
  report_fn, report_fn.getName()
