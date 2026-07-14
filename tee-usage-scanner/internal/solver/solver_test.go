package solver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

func bindingEntry() twe.Entry {
	return twe.Entry{
		ID:                  "TWE-BIND-001",
		Family:              twe.FamilyBinding,
		AcceptedSuppressors: []string{"authority_subject_derived_from_claim", "checked_inside_verifier", "test_or_dev_only"},
	}
}

func parseSARIF(t *testing.T, name string) []codeql.Result {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "codeql", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	res, err := codeql.ParseSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestSolveConfirmedFromRealSARIF drives the solver with the actual vulnerable
// SARIF: a modeled violation with no suppressor is Confirmed.
func TestSolveConfirmedFromRealSARIF(t *testing.T) {
	got := Solve(SolveInput{
		Entry: bindingEntry(), SiteID: "s1",
		BuildOK: true, QueryRan: true, Modeled: true,
		ViolationResults: parseSARIF(t, "binding_vulnerable.sarif"),
	})
	if got.Status != Confirmed {
		t.Fatalf("status=%q want confirmed (%s)", got.Status, got.Reason)
	}
	if !got.Status.IsReportedIssue() {
		t.Error("confirmed should be a reported issue")
	}
}

// TestSolveGuardedFromRealSARIF: the fixed SARIF has no violation, so the site
// is guarded, not reported.
func TestSolveGuardedFromRealSARIF(t *testing.T) {
	got := Solve(SolveInput{
		Entry: bindingEntry(), SiteID: "s1",
		BuildOK: true, QueryRan: true, Modeled: true,
		ViolationResults: parseSARIF(t, "binding_fixed.sarif"),
	})
	if got.Status != GuardedElsewhere {
		t.Fatalf("status=%q want guarded_elsewhere", got.Status)
	}
	if got.Status.IsReportedIssue() {
		t.Error("guarded_elsewhere must not be a reported issue")
	}
}

func hit() []codeql.Result {
	return []codeql.Result{{RuleID: "r", Path: "a.rs", StartLine: 1, Message: "v"}}
}

func TestSolveStatuses(t *testing.T) {
	e := bindingEntry()
	cases := []struct {
		name string
		in   SolveInput
		want Status
	}{
		{"out of scope", SolveInput{Entry: twe.Entry{}, BuildOK: true, QueryRan: true}, OutOfScope},
		{"unresolved no build", SolveInput{Entry: e, BuildOK: false, QueryRan: true, ViolationResults: hit()}, Unresolved},
		{"unresolved no query", SolveInput{Entry: e, BuildOK: true, QueryRan: false, ViolationResults: hit()}, Unresolved},
		{"guarded no violation", SolveInput{Entry: e, BuildOK: true, QueryRan: true}, GuardedElsewhere},
		{"violated candidate unmodeled", SolveInput{Entry: e, BuildOK: true, QueryRan: true, Modeled: false, ViolationResults: hit()}, ViolatedCandidate},
		{"confirmed", SolveInput{Entry: e, BuildOK: true, QueryRan: true, Modeled: true, ViolationResults: hit()}, Confirmed},
		{"test_only suppressor", SolveInput{Entry: e, BuildOK: true, QueryRan: true, Modeled: true, ViolationResults: hit(), Suppressors: []string{"test_or_dev_only"}}, TestOnly},
		{"delegated suppressor", SolveInput{Entry: e, BuildOK: true, QueryRan: true, Modeled: true, ViolationResults: hit(), Suppressors: []string{"checked_inside_verifier"}}, Delegated},
		{"guarded suppressor", SolveInput{Entry: e, BuildOK: true, QueryRan: true, Modeled: true, ViolationResults: hit(), Suppressors: []string{"authority_subject_derived_from_claim"}}, GuardedElsewhere},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Solve(tc.in); got.Status != tc.want {
				t.Fatalf("status=%q want %q (%s)", got.Status, tc.want, got.Reason)
			}
		})
	}
}

// TestUnacceptedSuppressorIgnored: a suppressor detected but NOT in the TWE's
// accepted list must not downgrade a real violation.
func TestUnacceptedSuppressorIgnored(t *testing.T) {
	got := Solve(SolveInput{
		Entry: bindingEntry(), SiteID: "s1",
		BuildOK: true, QueryRan: true, Modeled: true,
		ViolationResults: hit(),
		Suppressors:      []string{"some_unlisted_excuse"},
	})
	if got.Status != Confirmed {
		t.Fatalf("status=%q want confirmed (unaccepted suppressor must be ignored)", got.Status)
	}
}

// TestAcceptedSuppressorPriority: the TWE's accepted list order decides which
// of several detected suppressors applies.
func TestAcceptedSuppressorPriority(t *testing.T) {
	got := Solve(SolveInput{
		Entry: bindingEntry(), SiteID: "s1",
		BuildOK: true, QueryRan: true, Modeled: true,
		ViolationResults: hit(),
		// both detected; accepted-list order puts derived_from_claim first
		Suppressors: []string{"test_or_dev_only", "authority_subject_derived_from_claim"},
	})
	if got.AppliedSuppressor != "authority_subject_derived_from_claim" {
		t.Fatalf("applied=%q want authority_subject_derived_from_claim", got.AppliedSuppressor)
	}
	if got.Status != GuardedElsewhere {
		t.Fatalf("status=%q want guarded_elsewhere", got.Status)
	}
}

func TestClassifySuppressor(t *testing.T) {
	cases := map[string]Status{
		"test_or_dev_only":              TestOnly,
		"mode_gated_by_build_feature":   ConfigurationDependent,
		"mode_rejected_in_production":   ConfigurationDependent,
		"checked_inside_verifier":       Delegated,
		"authority_subject_derived_x":   GuardedElsewhere,
		"full_field_comparison_present": GuardedElsewhere,
	}
	for name, want := range cases {
		if got := classifySuppressor(name); got != want {
			t.Errorf("classify(%q)=%q want %q", name, got, want)
		}
	}
}
