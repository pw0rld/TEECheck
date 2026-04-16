/**
 * @name Off-chain output without chain binding
 * @description Off-chain worker output reaches on-chain or cross-service
 *              acceptance without chain, network, or identity binding.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/binding/unbound-offchain-output
 * @tags security
 *       tee
 *       binding
 */

import rust

from FnCall offchain_fn
where
  offchain_fn.getName().toLowerCase().matches([
    "%submit%", "%send%", "%relay%", "%bridge%", "%dispatch%"
  ])
  and not exists(PathExpr binding |
    binding.getTarget().getName().toLowerCase().matches([
      "%chain_id%", "%network%", "%session%", "%nonce%",
      "%block_hash%", "%epoch%"
    ])
    and offchain_fn.getAnArgument().getAChild*() = binding
  )
select offchain_fn,
  "Off-chain output submission $@ may lack chain, network, or identity binding.",
  offchain_fn, offchain_fn.getName()
