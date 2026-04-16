/**
 * @name Debug or simulation mode in production path
 * @description Debug, simulation, or dev mode reaches production launch
 *              or admission paths.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/config/debug-mode-in-production
 * @tags security
 *       tee
 *       config
 */

import rust

from Expr debug_check
where
  exists(PathExpr target |
    target.getTarget().getName().toLowerCase().matches([
      "%debug%", "%simulation%", "%sim_mode%", "%dev_mode%",
      "%test_mode%", "%unsafe%", "%insecure%"
    ])
    and debug_check.getAChild*() = target
  )
  and exists(FnCall prod_fn |
    prod_fn.getName().toLowerCase().matches([
      "%launch%", "%admit%", "%start%", "%init%", "%serve%"
    ])
  )
select debug_check,
  "Debug or simulation flag $@ may be reachable in production paths.",
  debug_check, debug_check.toString()
