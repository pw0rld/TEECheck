package codeql

import (
	"context"
	"strings"
	"testing"
)

func TestParseSARIFRetainsEveryThreadFlow(t *testing.T) {
	data := []byte(`{"runs":[{"artifacts":[{"location":{"uri":"src/a.c"}}],"logicalLocations":[{"kind":"function","fullyQualifiedName":"api::entry"}],"threadFlowLocations":[{"location":{"physicalLocation":{"artifactLocation":{"index":0},"region":{"startLine":7,"endLine":8}},"logicalLocations":[{"index":0}],"message":{"text":"input"}}}],"results":[{"ruleId":"cpp/teecheck-taint-trace","message":{"text":"may flow"},"relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"not-a-path.c"},"region":{"startLine":99}}}],"codeFlows":[{"threadFlows":[{"locations":[{"index":0},{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/b.c"},"region":{"startLine":20,"startColumn":2}},"logicalLocations":[{"kind":"function","name":"copy"}],"message":{"text":"write(dst)"}}}]},{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/c.c"},"region":{"startLine":30}},"message":{"text":"alternate"}}}]}]},{"threadFlows":[{"locations":[{}]}]}]}]}]}`)
	results, err := ParseSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Paths) != 3 {
		t.Fatalf("lost thread flows: %+v", results)
	}
	paths := results[0].Paths
	if len(paths[0]) != 2 || paths[0][0].Path != "src/a.c" || paths[0][0].StartLine != 7 || paths[0][0].EndLine != 8 || paths[0][0].Function != "api::entry" || paths[0][0].Expression != "input" {
		t.Fatalf("reference path not resolved: %+v", paths[0])
	}
	if paths[0][1].Function != "copy" || paths[0][1].StartColumn != 2 || paths[1][0].Path != "src/c.c" {
		t.Fatalf("inline path nodes lost: %+v", paths)
	}
	if len(paths[2]) != 1 || paths[2][0].Path != "" {
		t.Fatalf("missing node silently removed: %+v", paths[2])
	}
	if len(results[0].Related) != 1 {
		t.Fatal("legacy related location handling changed")
	}
}

func TestParseSARIFDoesNotInventPathsFromRelatedLocations(t *testing.T) {
	results, err := ParseSARIF([]byte(`{"runs":[{"results":[{"relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":1}}}]}]}]}`))
	if err != nil || len(results) != 1 || len(results[0].Paths) != 0 {
		t.Fatalf("related location promoted to a path: %+v, %v", results, err)
	}
}

func TestParseSARIFPathSnippetAndLogicalParent(t *testing.T) {
	results, err := ParseSARIF([]byte(`{"runs":[{"logicalLocations":[{"kind":"variable","parentIndex":1},{"kind":"function","name":"consumer"}],"results":[{"codeFlows":[{"threadFlows":[{"locations":[{"location":{"logicalLocations":[{"index":0}],"physicalLocation":{"artifactLocation":{"uri":"a.c"},"region":{"startLine":2,"snippet":{"text":"copy(data)"}}}}}]}]}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	step := results[0].Paths[0][0]
	if step.Function != "consumer" || step.Expression != "copy(data)" {
		t.Fatalf("missing path context: %+v", step)
	}
}

func TestAnalyzeMaxPathsOptIn(t *testing.T) {
	bin, argv := fakeCodeQL(t, "", "", emptySARIF, 0)
	engine := NewWithBin(bin)
	if _, err := engine.Analyze(context.Background(), AnalyzeOptions{DBPath: "db", Queries: []string{"trace.ql"}, MaxPaths: 10}); err != nil {
		t.Fatal(err)
	}
	args := readArgv(t, argv)
	if !strings.Contains(strings.Join(args, "\n"), "--max-paths=10") {
		t.Fatalf("path cap not passed: %v", args)
	}
	if _, err := engine.Analyze(context.Background(), AnalyzeOptions{DBPath: "db", Queries: []string{"trace.ql"}, MaxPaths: -1}); err == nil {
		t.Fatal("negative path cap accepted")
	}
}
