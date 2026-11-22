/**
 * @name Entry-surface parameter-to-sink flow clues
 * @description Records possible flows from structural entry signals to memory operations.
 *              A witness is an investigation lead, not a security verdict; no witness is not proof of safety.
 * @kind path-problem
 * @problem.severity recommendation
 * @id cpp/teecheck-entry-surface-taint
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

// Keep the structural signal used by the neutral program index. An entry may
// have internal wrappers/callers; requiring it to have no callers would discard
// useful dispatch and service boundaries.
predicate referencedByGlobalInitializer(Function function) {
  exists(FunctionAccess access, GlobalOrNamespaceVariable table |
    access.getTarget() = function and
    access = table.getInitializer().getExpr().getAChild*()
  )
}

predicate entrySignal(Function function, string signal) {
  signal = "global_function_pointer_initializer" and
  referencedByGlobalInitializer(function)
  or
  signal = "buffer_length_parameters" and
  not referencedByGlobalInitializer(function) and
  not function.isStatic() and
  not function.isCompilerGenerated() and
  exists(Parameter pointer, Parameter integral |
    pointer = function.getAParameter() and
    integral = function.getAParameter() and
    pointer != integral and
    pointer.getUnspecifiedType() instanceof PointerType and
    integral.getUnspecifiedType() instanceof IntegralType
  )
}

predicate entryParameter(Parameter parameter, string signal) {
  exists(FunctionDeclarationEntry definition, ParameterDeclarationEntry declaration |
    definition = definition.getFunction().getDefinition() and
    entrySignal(definition.getFunction(), signal) and
    declaration = definition.getAParameterDeclarationEntry() and
    parameter = declaration.getVariable()
  )
}

predicate entryNode(DataFlow::Node node, string signal) {
  exists(Parameter parameter |
    entryParameter(parameter, signal) and
    (node.asParameter() = parameter or
      (parameter.getUnspecifiedType() instanceof PointerType and node.asParameter(1) = parameter))
  )
}

// The sink name is always one of these identifiers. It is carried in fixed
// message metadata so Go need not guess a callee from arbitrary expression text.
predicate memoryOperation(string name) {
  name in [
    "memcpy", "memmove", "memset", "memcmp", "buf_compare_ct",
    "copy_from_user", "copy_to_user", "bb_memdup_user", "malloc", "calloc", "realloc"
  ]
}

predicate sinkNode(DataFlow::Node node, string kind, string functionName) {
  kind = "memory_call" and
  exists(FunctionCall call, Expr argument |
    memoryOperation(functionName) and
    call.getTarget().getName() = functionName and
    argument = call.getAnArgument() and
    (node.asExpr() = argument or
      (argument.getUnspecifiedType() instanceof PointerType and node.asIndirectExpr(1) = argument))
  )
  or
  kind = "array_index" and functionName = "" and
  exists(ArrayExpr access | node.asExpr() = access.getArrayOffset())
  or
  kind = "pointer_deref" and functionName = "" and
  exists(PointerDereferenceExpr access, Expr arithmetic |
    arithmetic = access.getOperand().getAChild*() and
    (arithmetic instanceof PointerAddExpr or arithmetic instanceof PointerSubExpr) and
    node.asExpr() = arithmetic
  )
}

module EntryToSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(string signal | entryNode(node, signal))
  }

  predicate isSink(DataFlow::Node node) {
    exists(string kind, string functionName | sinkNode(node, kind, functionName))
  }

  // This removes literal expression nodes only. There are deliberately no
  // guard, validation-function or crypto-directory safety assumptions here.
  predicate isBarrier(DataFlow::Node node) {
    node.asExpr() instanceof Literal
  }
}

module Flow = TaintTracking::Global<EntryToSinkConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, string signal, string kind, string functionName
where
  Flow::flowPath(source, sink) and
  entryNode(source.getNode(), signal) and
  sinkNode(sink.getNode(), kind, functionName)
select sink.getNode(), source, sink,
  "teecheck_entry_taint source_signal=" + signal + ";sink_kind=" + kind +
    ";sink_func=" + functionName
