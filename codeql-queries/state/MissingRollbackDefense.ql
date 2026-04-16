/**
 * @name Missing rollback or clone defense
 * @description Clone or rollback assumptions exist without a corresponding
 *              monotonicity or continuity defense.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/state/missing-rollback-defense
 * @tags security
 *       tee
 *       state
 */

import rust

from FnCall state_fn
where
  state_fn.getName().toLowerCase().matches([
    "%seal%", "%save%", "%persist%", "%commit%", "%write_state%"
  ])
  and not exists(FnCall monotonic |
    monotonic.getName().toLowerCase().matches([
      "%increment%", "%advance%", "%update_counter%", "%bump_epoch%",
      "%rotate%"
    ])
  )
select state_fn,
  "State sealing $@ may lack monotonicity or rollback defense.",
  state_fn, state_fn.getName()
