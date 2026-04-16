/**
 * @name Restored state without continuity binding
 * @description Restored or sealed state is not bound to epoch, network,
 *              version, or continuity metadata.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/state/unbound-restored-state
 * @tags security
 *       tee
 *       state
 */

import rust

from FnCall restore_fn
where
  restore_fn.getName().toLowerCase().matches([
    "%unseal%", "%restore%", "%recover%", "%load_state%",
    "%read_state%", "%deserialize%"
  ])
  and not exists(PathExpr binding |
    binding.getTarget().getName().toLowerCase().matches([
      "%epoch%", "%version%", "%network_id%", "%chain_id%",
      "%nonce%", "%counter%", "%generation%"
    ])
    and restore_fn.getAnArgument().getAChild*() = binding
  )
select restore_fn,
  "State restoration $@ may not verify epoch, network, or version binding.",
  restore_fn, restore_fn.getName()
