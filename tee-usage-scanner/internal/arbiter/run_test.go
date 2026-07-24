package arbiter

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// TestBuildPacket_SurfacesUntypedSections confirms the packet
// rendering catches both untyped surfaces a human reviewer would
// otherwise miss when scanning the packet markdown alone.
func TestBuildPacket_SurfacesUntypedSections(t *testing.T) {
	pack := artifacts.CasePack{CaseID: "case-001", Category: "tee", Priority: "high"}
	h := artifacts.Hypothesis{
		Title:        "test hypothesis",
		Summary:      "summary",
		UntypedFacts: []string{"tool-hit-line-42"},
	}
	c := artifacts.Challenge{}
	m := artifacts.VerificationMemo{
		Status:                "inconclusive",
		UntypedConfirmedFacts: []string{"legacy-confirm-text"},
		UntypedContradictions: []string{"legacy-contradict-text"},
	}
	item := artifacts.FindingItem{Status: "needs_review", Confidence: "low"}
	sections := buildSections(pack, h, c, m, caseContext{}, artifacts.ChallengerIndependentView{})
	body := buildPacket(pack, h, c, m, item, sections)

	for _, want := range []string{
		"Unanchored context",
		"[unanchored] tool-hit-line-42",
		"Unanchored confirmed",
		"[unanchored] legacy-confirm-text",
		"Unanchored contradictions",
		"[unanchored] legacy-contradict-text",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("packet missing %q\n--- packet ---\n%s", want, body)
		}
	}
}

// TestTaggedJoin pins the prompt-formatting helper used by
// arbitrateLLM so untyped items reach the LLM with explicit tags
// rather than as a bare strings list.
func TestTaggedJoin(t *testing.T) {
	if got := taggedJoin(nil, "[unanchored]"); got != "(none)" {
		t.Errorf("nil: %q want (none)", got)
	}
	if got := taggedJoin([]string{"a", "b"}, "[unanchored]"); got != "[unanchored] a | [unanchored] b" {
		t.Errorf("got %q", got)
	}
}

// CitedFact is referenced from imported package; touch it once so
// imports stay tidy if test variants are added.
var _ = citations.CitedFact{}
