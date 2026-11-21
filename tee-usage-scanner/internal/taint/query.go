package taint

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

var queryIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// BuildQuery materializes one fixed C/C++ path-query template. Only validated
// identifiers, an exact indexed source definition, and integer parameters are
// interpolated. Callers cannot supply QL predicates, imports, or expressions.
func BuildQuery(p Parameters, source artifacts.Symbol) (string, error) {
	if !queryIdentifier.MatchString(p.SourceFunc) || source.Name != p.SourceFunc || source.StartLine <= 0 || !querySourcePath(source.File) {
		return "", fmt.Errorf("taint source must identify an indexed function definition")
	}
	if p.SourcePath != "" && p.SourcePath != source.File {
		return "", fmt.Errorf("taint source_path differs from selected definition")
	}
	if p.SourceParamIndex < -1 {
		return "", fmt.Errorf("source_param_index must be -1 or non-negative")
	}
	if p.SinkFunc != "" && !queryIdentifier.MatchString(p.SinkFunc) {
		return "", fmt.Errorf("sink_func must be a C/C++ identifier")
	}
	switch p.SinkKind {
	case "":
		if p.SinkFunc == "" {
			return "", fmt.Errorf("sink_func or sink_kind is required")
		}
	case "memory_copy", "function_call":
		if p.SinkKind == "function_call" && p.SinkFunc == "" {
			return "", fmt.Errorf("function_call requires sink_func")
		}
	case "array_index", "pointer_deref":
		if p.SinkFunc != "" {
			return "", fmt.Errorf("sink_func cannot be combined with %s; use sink_kind alone for expression sinks", p.SinkKind)
		}
	default:
		return "", fmt.Errorf("unsupported sink_kind %q", p.SinkKind)
	}
	if len(p.BarrierFuncs) > 8 {
		return "", fmt.Errorf("at most 8 barrier_funcs are allowed")
	}
	barriers := append([]string(nil), p.BarrierFuncs...)
	for _, name := range barriers {
		if !queryIdentifier.MatchString(name) {
			return "", fmt.Errorf("barrier function must be a C/C++ identifier")
		}
	}
	sort.Strings(barriers)
	var barrierNames []string
	for _, name := range barriers {
		if len(barrierNames) == 0 || strconv.Quote(name) != barrierNames[len(barrierNames)-1] {
			barrierNames = append(barrierNames, strconv.Quote(name))
		}
	}
	barrier := "none()"
	if len(barrierNames) > 0 {
		barrier = "exists(FunctionCall call | node.asExpr() = call and call.getTarget().getName() in [" + strings.Join(barrierNames, ", ") + "])"
	}
	parameter := ""
	if p.SourceParamIndex >= 0 {
		parameter = fmt.Sprintf("and parameter.getIndex() = %d", p.SourceParamIndex)
	}
	sink := querySink(p)
	return fmt.Sprintf(`/**
 * @name Parameterized source-to-sink taint witnesses
 * @description Records possible data-flow witnesses; no match or a configured barrier is not proof of safety.
 * @kind path-problem
 * @problem.severity recommendation
 * @id cpp/teecheck-taint-trace
 */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

predicate selectedSourceParameter(Parameter parameter) {
  exists(FunctionDeclarationEntry definition, ParameterDeclarationEntry declaration |
    definition = definition.getFunction().getDefinition() and
    definition.getFunction().getName() = %s and
    definition.getFile().getRelativePath() = %s and
    definition.getLocation().getStartLine() = %d and
    declaration = definition.getAParameterDeclarationEntry() and
    parameter = declaration.getVariable()
    %s
  )
}

module TraceConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(Parameter parameter |
      selectedSourceParameter(parameter) and
      (node.asParameter() = parameter or
        (parameter.getUnspecifiedType() instanceof PointerType and node.asParameter(1) = parameter))
    )
  }

  predicate isSink(DataFlow::Node node) {
    %s
  }

  // This removes only the configured call-result expression nodes. It is
  // syntactic filtering, not proof of a validated input or a dominating guard.
  predicate isBarrier(DataFlow::Node node) {
    %s
  }
}

module Flow = TaintTracking::Global<TraceConfiguration>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Possible parameter-to-sink taint witness; configured barriers are syntactic filters, not safety proofs."
`, strconv.Quote(p.SourceFunc), strconv.Quote(filepath.ToSlash(source.File)), source.StartLine, parameter, sink, barrier), nil
}

func querySink(p Parameters) string {
	if p.SinkKind == "array_index" {
		return "exists(ArrayExpr access | node.asExpr() = access.getArrayOffset())"
	}
	if p.SinkKind == "pointer_deref" {
		return "exists(PointerDereferenceExpr access | node.asExpr() = access.getOperand())"
	}
	target := "exists(call.getTarget())"
	if p.SinkFunc != "" {
		target = "call.getTarget().getName() = " + strconv.Quote(p.SinkFunc)
	} else if p.SinkKind == "memory_copy" {
		target = `call.getTarget().getName() in ["memcpy", "memmove", "copy_from_user", "bb_memdup_user"]`
	}
	return `exists(FunctionCall call, Expr argument |
      ` + target + ` and argument = call.getAnArgument() and
      (node.asExpr() = argument or
        (argument.getUnspecifiedType() instanceof PointerType and node.asIndirectExpr(1) = argument))
    )`
}

func querySourcePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && !strings.Contains(path, "\\") && path != "." &&
		filepath.ToSlash(filepath.Clean(path)) == path && path != ".." && !strings.HasPrefix(path, "../")
}
