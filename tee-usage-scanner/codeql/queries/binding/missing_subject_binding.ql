/**
 * @name Unbound attested subject authority
 * @description A function verifies an attestation quote but never references
 *              the attested key field, so authority is granted to a subject
 *              not bound to the attested identity (TWE-BIND-001).
 * @kind problem
 * @problem.severity error
 * @id teecheck/binding/missing-subject-binding
 * @tags security
 */
import rust

from Function f
where
  exists(Call call |
    call.getEnclosingCallable() = f and
    call.getStaticTarget().getName().getText() = "verify_quote"
  ) and
  not exists(FieldExpr fe |
    fe.getEnclosingCallable() = f and
    fe.getIdentifier().getText() = "pubkey"
  )
select f, "TWE-BIND-001: verifies an attestation quote but never binds authority to the attested key"
