/**
 * @name Signature accepted without encoded-length completeness check
 * @description A signature-verification function reaches acceptance (*stat = 1)
 *              without verifying that the ASN.1-encoded length matches the
 *              decoded length — the check CVE-2016-6129's fix adds via
 *              der_length_sequence. TWE-GUARD-001 (validity-only consumption),
 *              C/C++ variant.
 * @kind problem
 * @problem.severity error
 * @id teecheck/guard/c-missing-length-check
 * @tags security
 */
import cpp

// NOTE: in the TWE pipeline the authority point is pinned to the site the
// expert located (file + line), which scopes this to the one target function.
// Run unscoped it flags every verifier that sets *stat=1 without the check;
// that breadth is expected and handled by TrustIR scoping.
from Function f
where
  exists(Assignment a |
    a.getEnclosingFunction() = f and
    a.getFile().getBaseName() = "rsa_verify_hash.c" and
    a.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getName() = "stat"
  ) and
  not exists(FunctionCall c |
    c.getEnclosingFunction() = f and
    c.getTarget().getName() = "der_length_sequence"
  )
select f, "TWE-GUARD-001: " + f.getName() + " accepts a signature without the encoded-length completeness check"
