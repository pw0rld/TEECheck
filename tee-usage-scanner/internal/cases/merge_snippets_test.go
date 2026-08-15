package cases

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// TestMergeSnippets_PreservesExisting: pre-existing (deterministic-lane
// definition) snippets survive a merge with freshly collected generic
// ones instead of being overwritten — the CVE-2026-44362 evidence-window
// regression this merge exists to prevent.
func TestMergeSnippets_PreservesExisting(t *testing.T) {
	definition := artifacts.PromptSnippet{Path: "big.c", StartLine: 300, EndLine: 340, Content: "authority body"}
	collected := []artifacts.PromptSnippet{
		{Path: "big.c", StartLine: 300, EndLine: 350, Content: "window around first mention"},
		{Path: "small.c", StartLine: 1, EndLine: 10, Content: "whole file"},
	}
	got := mergeSnippets([]artifacts.PromptSnippet{definition}, collected)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (dedup by path+start)", len(got))
	}
	if got[0].Content != "authority body" {
		t.Errorf("pre-existing snippet must come first and intact, got %q", got[0].Content)
	}
	if got[1].Path != "small.c" {
		t.Errorf("collected non-duplicate missing, got %+v", got[1])
	}
}

// TestMergeSnippets_ContainmentEitherDirection (codex-R2 finding 5): a
// collected snippet redundant with an existing definition is dropped
// whether it is a window INSIDE the definition or the generic WHOLE-FILE
// snippet that CONTAINS it — the OP-TEE producer case.
func TestMergeSnippets_ContainmentEitherDirection(t *testing.T) {
	definition := artifacts.PromptSnippet{Path: "producer.c", StartLine: 260, EndLine: 290, Content: "definition"}
	// Whole-file snippet (different start line, so exact-key dedup does
	// not fire) CONTAINING the definition.
	wholeFile := artifacts.PromptSnippet{Path: "producer.c", StartLine: 1, EndLine: 411, Content: "whole file"}
	got := mergeSnippets([]artifacts.PromptSnippet{definition}, []artifacts.PromptSnippet{wholeFile})
	if len(got) != 1 || got[0].Content != "definition" {
		t.Errorf("whole-file snippet containing the definition must be dropped, got %+v", got)
	}
	// Window inside the definition: also dropped.
	window := artifacts.PromptSnippet{Path: "producer.c", StartLine: 265, EndLine: 275, Content: "inner window"}
	got = mergeSnippets([]artifacts.PromptSnippet{definition}, []artifacts.PromptSnippet{window})
	if len(got) != 1 || got[0].Content != "definition" {
		t.Errorf("window inside the definition must be dropped, got %+v", got)
	}
	// Partial overlap only: BOTH kept (neither contains the other).
	partial := artifacts.PromptSnippet{Path: "producer.c", StartLine: 280, EndLine: 320, Content: "overlapping tail"}
	got = mergeSnippets([]artifacts.PromptSnippet{definition}, []artifacts.PromptSnippet{partial})
	if len(got) != 2 {
		t.Errorf("partial overlap must keep both, got %+v", got)
	}
}

// TestMergeSnippets_NoExistingIsIdentity: planner packs arrive empty;
// merge must be exactly the collected list.
func TestMergeSnippets_NoExistingIsIdentity(t *testing.T) {
	collected := []artifacts.PromptSnippet{{Path: "a.c", StartLine: 1, EndLine: 2, Content: "x"}}
	got := mergeSnippets(nil, collected)
	if len(got) != 1 || got[0].Path != "a.c" {
		t.Errorf("identity over collected failed: %+v", got)
	}
}
