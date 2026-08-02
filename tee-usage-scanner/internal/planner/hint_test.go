package planner

import (
	"strings"
	"testing"
)

// The caller's concern must reach the prompt verbatim. Without it the run
// has no way to be told "I suspect the TA loading path", which is the whole
// point of scanning a repository rather than a hand-picked file: the scope
// is wide, so the priority has to come from somewhere.
func TestBuildRoundPrompt_CarriesTheCallersHint(t *testing.T) {
	const hint = "we suspect the TA loading path mishandles rollback state"
	got := BuildRoundPrompt(&PlannerState{}, PromptProfile{RepoURL: "https://example.invalid/r", Hint: hint}, Budget{}, nil)
	if !strings.Contains(got, hint) {
		t.Fatalf("profile block must carry the hint verbatim:\n%s", got)
	}
}

// A hint is a priority, not a finding. A run that restates the caller's
// suspicion as its conclusion has measured nothing, so the prompt must say
// so next to the hint itself rather than trusting a rule ten lines away.
func TestBuildRoundPrompt_HintIsFramedAsAPriorityNotAConclusion(t *testing.T) {
	got := strings.ToLower(BuildRoundPrompt(&PlannerState{}, PromptProfile{Hint: "check the loader"}, Budget{}, nil))
	for _, want := range []string{"not a finding", "does not support"} {
		if !strings.Contains(got, want) {
			t.Errorf("hint framing must say %q so the concern is not treated as evidence:\n%s", want, got)
		}
	}
}

// No hint, no section — the default run must look exactly as it did.
func TestBuildRoundPrompt_NoHintRendersNothing(t *testing.T) {
	got := strings.ToLower(BuildRoundPrompt(&PlannerState{}, PromptProfile{RepoURL: "https://example.invalid/r"}, Budget{}, nil))
	if strings.Contains(got, "concern") {
		t.Fatalf("an empty hint must render no section:\n%s", got)
	}
}
