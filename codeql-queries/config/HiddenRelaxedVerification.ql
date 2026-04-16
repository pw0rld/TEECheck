/**
 * @name Hidden relaxed verification in wrappers
 * @description Helper wrappers hide relaxed verification, feature-gated
 *              bypasses, or environment-dependent trust assumptions.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/config/hidden-relaxed-verification
 * @tags security
 *       tee
 *       config
 */

import rust

from FnCall wrapper_fn
where
  wrapper_fn.getName().toLowerCase().matches([
    "%verify%", "%validate%", "%check%", "%authenticate%"
  ])
  and exists(Expr conditional |
    conditional.toString().toLowerCase().matches([
      "%cfg!(%)%", "%feature%", "%debug_assert!", "%if debug%",
      "%if test%", "%if env%"
    ])
    and wrapper_fn.getScope().getAChild*() = conditional
  )
select wrapper_fn,
  "Verification wrapper $@ may have feature-gated or environment-dependent relaxed paths.",
  wrapper_fn, wrapper_fn.getName()
