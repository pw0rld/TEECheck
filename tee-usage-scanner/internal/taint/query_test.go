package taint

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func querySource() artifacts.Symbol {
	return artifacts.Symbol{SymbolID: "cpp:src/entry.c:11:entry(char*)", Name: "entry", File: "src/entry.c", StartLine: 11}
}
func queryParameters() Parameters {
	return Parameters{SourceFunc: "entry", SourceParamIndex: -1, SinkKind: "memory_copy"}
}

func TestBuildQueryUsesBoundDefinitionAndModularPathAPI(t *testing.T) {
	p := queryParameters()
	p.SourceParamIndex = 2
	p.BarrierFuncs = []string{"check_z", "check_a", "check_a"}
	query, err := BuildQuery(p, querySource())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@kind path-problem", "@id cpp/teecheck-taint-trace", "implements DataFlow::ConfigSig", "TaintTracking::Global<TraceConfiguration>", "import Flow::PathGraph", "Flow::flowPath(source, sink)", `getRelativePath() = "src/entry.c"`, `getStartLine() = 11`, "parameter.getIndex() = 2", "node.asParameter() = parameter", "node.asParameter(1) = parameter", `["check_a", "check_z"]`} {
		if !strings.Contains(query, want) {
			t.Errorf("query missing %q", want)
		}
	}
	for _, bad := range []string{"TaintTracking::Configuration", "asIndirectParameter", "satisfied", "controls("} {
		if strings.Contains(query, bad) {
			t.Errorf("query contains unsupported or overclaiming API %q", bad)
		}
	}
	if !strings.Contains(query, "node.asExpr() = call and call.getTarget()") {
		t.Fatal("barrier must filter only call results")
	}
}

func TestBuildQuerySupportsEachSinkKind(t *testing.T) {
	for _, tc := range []struct{ kind, name, expression string }{
		{"memory_copy", "", `"memcpy", "memmove", "copy_from_user", "bb_memdup_user"`},
		{"memory_copy", "copy_checked", `call.getTarget().getName() = "copy_checked"`},
		{"function_call", "consume", `call.getTarget().getName() = "consume"`},
		{"array_index", "", "access.getArrayOffset()"},
		{"pointer_deref", "", "access.getOperand()"},
	} {
		t.Run(tc.kind+tc.name, func(t *testing.T) {
			p := queryParameters()
			p.SinkKind, p.SinkFunc = tc.kind, tc.name
			query, err := BuildQuery(p, querySource())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(query, tc.expression) {
				t.Errorf("missing sink selector %q", tc.expression)
			}
			if strings.Contains(query, "parameter.getIndex() =") {
				t.Fatal("default should include all parameters")
			}
		})
	}
}

func TestBuildQueryRejectsUntrustedSelectors(t *testing.T) {
	for _, mutate := range []func(*Parameters, *artifacts.Symbol){
		func(p *Parameters, _ *artifacts.Symbol) { p.SourceFunc = `entry" or 1=1` },
		func(p *Parameters, _ *artifacts.Symbol) { p.SinkFunc = `copy); select f` },
		func(p *Parameters, _ *artifacts.Symbol) { p.BarrierFuncs = []string{"check/*"} },
		func(p *Parameters, _ *artifacts.Symbol) { p.BarrierFuncs = make([]string, 9) },
		func(p *Parameters, _ *artifacts.Symbol) { p.SourceParamIndex = -2 },
		func(p *Parameters, _ *artifacts.Symbol) { p.SourcePath = "other.c" },
		func(p *Parameters, _ *artifacts.Symbol) { p.SinkKind = "arbitrary_ql" },
		func(p *Parameters, _ *artifacts.Symbol) { p.SinkKind = "array_index"; p.SinkFunc = "consume" },
		func(p *Parameters, _ *artifacts.Symbol) { p.SinkKind = "function_call" },
		func(_ *Parameters, s *artifacts.Symbol) { s.File = "../outside.c" },
		func(_ *Parameters, s *artifacts.Symbol) { s.StartLine = 0 },
	} {
		p, source := queryParameters(), querySource()
		mutate(&p, &source)
		if _, err := BuildQuery(p, source); err == nil {
			t.Errorf("untrusted parameters accepted: %+v %+v", p, source)
		}
	}
}
