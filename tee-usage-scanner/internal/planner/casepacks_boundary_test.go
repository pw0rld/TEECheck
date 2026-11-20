package planner

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"testing"
)

func TestDedupePacksSubsetKeepsAllEvidence(t *testing.T) {
	a := artifacts.CasePack{CaseID: "a", Category: "attestation", TargetFiles: []string{"main.c"}, TargetSymbols: []string{"verify"}, Snippets: []artifacts.PromptSnippet{{Path: "main.c", Content: "first"}}, ToolFactRefs: []string{"fact-a"}, WhySelected: []string{"why-a"}, KnowledgeHints: []artifacts.KnowledgeHint{{Path: "wiki-a"}}}
	b := artifacts.CasePack{CaseID: "b", Category: "attestation", TargetFiles: []string{"main.c", "helper.c"}, TargetSymbols: []string{"verify"}, Snippets: []artifacts.PromptSnippet{{Path: "helper.c", Content: "second"}}, ToolFactRefs: []string{"fact-b"}, WhySelected: []string{"why-b"}, KnowledgeHints: []artifacts.KnowledgeHint{{Path: "wiki-b"}}, ExpectedObligations: []string{"binding"}, ToolFacts: []string{"tool-b"}}
	got := DedupePacks([]artifacts.CasePack{a, b})
	if len(got) != 1 {
		t.Fatalf("same symbol with subset files should merge: %+v", got)
	}
	p := got[0]
	if len(p.TargetFiles) != 2 || len(p.Snippets) != 2 || len(p.ToolFactRefs) != 2 || len(p.WhySelected) != 2 || len(p.KnowledgeHints) != 2 || len(p.ExpectedObligations) != 1 || len(p.ToolFacts) != 1 {
		t.Fatalf("evidence lost during merge: %+v", p)
	}
}

func TestDedupePacksSamePrimaryCategoryMergesSparseTargets(t *testing.T) {
	a := artifacts.CasePack{Category: "state_machine", TargetFiles: []string{"main.c", "a.c"}}
	b := artifacts.CasePack{Category: "state_machine", TargetFiles: []string{"main.c", "b.c"}, TargetSymbols: []string{"resume"}}
	if got := DedupePacks([]artifacts.CasePack{a, b}); len(got) != 1 {
		t.Fatalf("same main target/category should merge: %+v", got)
	}
}

func TestDedupePacksDoesNotMergeDistinctSymbolsOrCategories(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b artifacts.CasePack
	}{
		{"symbols", artifacts.CasePack{Category: "state_machine", TargetFiles: []string{"main.c"}, TargetSymbols: []string{"save"}}, artifacts.CasePack{Category: "state_machine", TargetFiles: []string{"main.c"}, TargetSymbols: []string{"resume"}}},
		{"categories", artifacts.CasePack{Category: "attestation", TargetFiles: []string{"main.c"}}, artifacts.CasePack{Category: "key_management", TargetFiles: []string{"main.c"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DedupePacks([]artifacts.CasePack{tc.a, tc.b}); len(got) != 2 {
				t.Fatalf("distinct review targets merged: %+v", got)
			}
		})
	}
}
