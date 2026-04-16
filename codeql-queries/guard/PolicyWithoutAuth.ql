/**
 * @name Policy-changing surface without authentication
 * @description Policy-changing surfaces exist without explicit caller
 *              authentication or authorization.
 * @kind problem
 * @problem.severity warning
 * @id tee-audit/guard/policy-without-auth
 * @tags security
 *       tee
 *       guard
 */

import rust

from FnCall policy_fn
where
  policy_fn.getName().toLowerCase().matches([
    "%set_policy%", "%update_policy%", "%change_config%",
    "%add_peer%", "%remove_peer%", "%set_key%"
  ])
  and not exists(FnCall auth |
    auth.getName().toLowerCase().matches([
      "%authenticate%", "%authorize%", "%verify_permission%",
      "%check_acl%", "%is_authorized%"
    ])
  )
select policy_fn,
  "Policy-changing function $@ may lack explicit authentication.",
  policy_fn, policy_fn.getName()
