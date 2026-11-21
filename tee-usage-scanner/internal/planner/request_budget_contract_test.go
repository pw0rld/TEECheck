package planner

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func TestConvergencePromptRetainsContractAndLeadBeforeNavigation(t *testing.T) {
	state := NewState("run-1")
	state.AuditLeads = []artifacts.AuditLead{{
		RunID: "run-1", LeadID: "lead-s1-001", SampleIndex: 1,
		TargetSymbolIDs: []artifacts.SymbolID{"source.c::validate"},
		ReasonFactRefs:  []string{"obs:1:2:0:source"},
	}}
	state.Rounds = []artifacts.RoundRecord{{Observations: []artifacts.RoundObservation{
		{Name: "get_repository_card", OK: true, Output: strings.Repeat("oversized navigation", 1000)},
		{Name: "read_file", OK: true, Ref: "obs:1:2:0:source", Output: "1: int validate(void) { return 1; }"},
	}}}
	paths := map[string]bool{"source.c": true}
	for i := 0; i < 1000; i++ {
		paths[fmt.Sprintf("navigation/path-%04d.c", i)] = true
	}
	const available = 5000
	system, prompt := convergencePrompt(state, paths, available)
	for _, want := range []string{"\"case_invariants\":[]", "\"lead_ref\"", "\"preconditions\"", "\"required_property\"", "\"verification_queries\":[]", "lead-s1-001", "source.c::validate", "obs:1:2:0:source", "int validate(void)"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("compact prompt lost %q", want)
		}
	}
	leadAt := strings.Index(prompt, "lead-s1-001")
	if leadAt >= strings.Index(prompt, "OBSERVED PATHS") || leadAt >= strings.Index(prompt, "Recent successful observations") {
		t.Fatal("navigation precedes the lead needed to formalize a contract")
	}
	if strings.Contains(prompt, "oversized navigation") {
		t.Fatal("oversized navigation displaced bounded source context")
	}
	if got := requestInputUpperBound(system, prompt) + minimumReplyTokens; got > available {
		t.Fatalf("request and reply reservation use %d bytes, budget %d", got, available)
	}
}

func TestConvergencePromptBoundsTinyBudgetsWithoutCuttingRecords(t *testing.T) {
	state := NewState("run-1")
	state.AuditLeads = []artifacts.AuditLead{{RunID: "run-1", LeadID: "lead-" + strings.Repeat("界", 10000)}}
	for _, available := range []int{0, 200, 700, 1000, 2000, 5000, 20000} {
		t.Run(fmt.Sprint(available), func(t *testing.T) {
			system, prompt := convergencePrompt(state, map[string]bool{"目录/源码.c": true}, available)
			if !utf8.ValidString(prompt) {
				t.Fatal("prompt cut through a UTF-8 code point")
			}
			if strings.Contains(prompt, "lead-") {
				t.Fatal("an oversized lead must be omitted whole")
			}
			minimum := requestInputUpperBound(system, "") + minimumReplyTokens
			if available >= minimum && requestInputUpperBound(system, prompt)+minimumReplyTokens > available {
				t.Fatal("compact prompt spends its bounded reply reservation")
			}
			if available < minimum && prompt != "" {
				t.Fatal("no prompt fits below the fixed request and reply reservation")
			}
		})
	}
}

func TestConvergencePromptKeepsOnlyCurrentRunLeadIdentities(t *testing.T) {
	state := NewState("current")
	state.AuditLeads = []artifacts.AuditLead{
		{RunID: "old", LeadID: "unrelated-lead"},
		{RunID: "current", LeadID: "current-lead"},
	}
	_, prompt := convergencePrompt(state, nil, 5000)
	if strings.Contains(prompt, "unrelated-lead") || !strings.Contains(prompt, "current-lead") {
		t.Fatal("compact prompt does not preserve current-run lead isolation")
	}
	if !strings.Contains(prompt, "Preserve candidates with missing grounding") || !strings.Contains(prompt, "never weaken the obligation") {
		t.Fatal("compact prompt lost the unsupported-candidate or query boundary")
	}
}
