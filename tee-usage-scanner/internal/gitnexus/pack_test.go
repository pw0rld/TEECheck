package gitnexus

import "testing"

func TestBuildKnowledgePack(t *testing.T) {
	export := Export{
		SourcePath: "/tmp/project",
		Nodes: []Node{
			{ID: "1", Type: "file", Name: "verify.js", Path: "src/verify.js"},
			{ID: "2", Type: "function", Name: "verifyQeIdentityPolicy", File: "src/verify.js"},
			{ID: "3", Type: "function", Name: "sessionCheck", File: "src/session.js"},
		},
		Edges: []Edge{
			{Source: "1", Target: "2", Type: "contains"},
			{Source: "2", Target: "3", Type: "calls"},
			{Source: "1", Target: "3", Type: "imports"},
		},
	}

	pack := BuildKnowledgePack("fixtures/gitnexus/sample_graph.json", export, "tee")
	if pack.Source.NodeCount != 3 {
		t.Fatalf("expected 3 nodes, got %d", pack.Source.NodeCount)
	}
	if len(pack.RelevantFiles) == 0 {
		t.Fatalf("expected relevant files")
	}
	if len(pack.AuditQuestions) == 0 {
		t.Fatalf("expected audit questions")
	}
	if got := pack.RelevantFiles[0].Label; got != "verify.js" {
		t.Fatalf("expected top file verify.js, got %s", got)
	}
}

func TestBuildKnowledgePackDoesNotTreatSymbolsAsFiles(t *testing.T) {
	export := Export{
		SourcePath: "/tmp/project",
		Nodes: []Node{
			{ID: "1", Type: "file", Name: "state.rs", Path: "runtime-sdk/src/state.rs"},
			{ID: "2", Type: "function", Name: "with", Path: "runtime-sdk/src/state.rs", File: "runtime-sdk/src/state.rs"},
		},
		Edges: []Edge{
			{Source: "1", Target: "2", Type: "contains"},
		},
	}

	pack := BuildKnowledgePack("reports/oasis-sdk-gitnexus-graph.json", export, "runtime")
	if len(pack.RelevantFiles) != 1 {
		t.Fatalf("expected 1 relevant file, got %d", len(pack.RelevantFiles))
	}
	if pack.RelevantFiles[0].Label != "state.rs" {
		t.Fatalf("expected state.rs as relevant file, got %s", pack.RelevantFiles[0].Label)
	}
}
