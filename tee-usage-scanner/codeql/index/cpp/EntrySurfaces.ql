/**
 * @name Entry surface structure
 * @description Records neutral definition and interface signals for navigation.
 *              These do not prove external reachability or untrusted input.
 * @kind table
 * @id cpp/teecheck-index-entry-surfaces
 *
 * Columns: name, file, start_line, end_line, signature, module, signal,
 *          evidence_file, evidence_start_line, evidence_end_line, detail.
 */

import cpp
import Index

predicate surfaceSignal(
  FunctionDeclarationEntry d, string signal, Element evidence, string detail
) {
  // The definition row lets the consumer attach other observed graph signals
  // while keeping the complete definition range. It is not a surface signal.
  signal = "definition" and evidence = d and detail = "indexed definition"
  or
  // Restrict this conservative subset to global namespace free functions.
  // Namespace exports and platform visibility attributes are not inferred.
  signal = "external_linkage" and
  d.getFunction().hasGlobalName(d.getFunction().getName()) and
  not d.getFunction().isStatic() and
  not d.getFunction().isCompilerGenerated() and
  evidence = d and
  detail = "non-static global-namespace definition; runtime reachability unproven"
  or
  signal = "global_function_pointer_initializer" and
  exists(FunctionAccess access, GlobalOrNamespaceVariable table |
    access.getTarget() = d.getFunction() and
    access = table.getInitializer().getExpr().getAChild*() and
    evidence = access and
    detail = "function reference in initializer of " + table.getQualifiedName() +
      "; dispatch purpose and runtime use unproven"
  )
  or
  signal = "buffer_length_parameters" and
  exists(Parameter pointer, Parameter integral |
    pointer = d.getFunction().getAParameter() and
    integral = d.getFunction().getAParameter() and
    pointer != integral and
    pointer.getUnspecifiedType() instanceof PointerType and
    integral.getUnspecifiedType() instanceof IntegralType and
    evidence = d and
    detail = "pointer parameter " + pointer.getIndex().toString() +
      " and integral parameter " + integral.getIndex().toString() +
      "; buffer/length relationship and input origin unproven"
  )
}

from FunctionDeclarationEntry d, string signal, Element evidence, string detail
where
  d = definitionOf(d.getFunction()) and
  surfaceSignal(d, signal, evidence, detail) and
  exists(evidence.getFile().getRelativePath())
select d.getFunction().getName(), d.getFile().getRelativePath(),
  d.getLocation().getStartLine(), d.getLocation().getEndLine(),
  d.getFunction().getParameterString(), moduleOf(d.getFile()), signal,
  evidence.getFile().getRelativePath(), evidence.getLocation().getStartLine(),
  evidence.getLocation().getEndLine(), detail
