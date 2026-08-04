package artifacts

import (
	"strings"
	"testing"
)

// The query's own conclusion is the evidence. RollbackVersionNotPropagated
// computes "producer X never propagates rollback field 'version'; authority Y
// therefore checks a default version" and names three sites — and on
// 2026-07-31 the agents were handed "status=success
// locations=core/crypto/signed_hdr.c:262" and nothing else. Across five agent
// prompts, check_update_version and ree_fs_ta appeared zero times, while
// CodeQL had resolved both.
func TestFormatToolFact_CarriesTheMessageAndRelatedSites(t *testing.T) {
	f := ToolFact{
		FactID: "trustir-cpp-x", Tool: "trustir-cpp",
		Operation: "cpp.state.rollback_version_propagation", Status: "success",
		Locations: []ToolLocation{{Path: "core/crypto/signed_hdr.c", StartLine: 262}},
		Findings: []ToolFinding{{
			Message:  "TWE-STATE-001: producer never propagates rollback field 'version'; authority therefore checks a default version.",
			Location: ToolLocation{Path: "core/crypto/signed_hdr.c", StartLine: 262},
			Related: []ToolLocation{
				{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
				{Path: "core/kernel/ree_fs_ta.c", StartLine: 639, Symbol: "check_update_version"},
			},
		}},
	}
	got := FormatToolFact(f)

	for _, want := range []string{
		"never propagates rollback field", // the conclusion
		"check_update_version",            // the symbol
		"core/kernel/ree_fs_ta.c:639",     // the consumer's location
		"shdr_load_pub_key",
		"status=success",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered fact must contain %q:\n%s", want, got)
		}
	}
}

// A fact with no findings still renders — the old shape must not regress.
func TestFormatToolFact_ZeroResultStillStatesItself(t *testing.T) {
	got := FormatToolFact(ToolFact{
		FactID: "trustir-cpp-y", Tool: "trustir-cpp",
		Operation: "cpp.state.rollback_version_propagation", Status: "success",
	})
	if !strings.Contains(got, "status=success") {
		t.Errorf("got %q", got)
	}
	// "we looked and found nothing" must be sayable, not an empty line.
	if !strings.Contains(got, "no match") {
		t.Errorf("a zero-result fact must state that it matched nothing: %q", got)
	}
}
