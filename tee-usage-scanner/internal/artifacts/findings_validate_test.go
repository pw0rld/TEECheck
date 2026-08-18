package artifacts

import (
	"strings"
	"testing"
)

func validFindingsForValidation() Findings {
	return Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "run-001",
		Findings: []FindingItem{{
			FindingID:  "finding-001",
			SliceID:    "case-001",
			Status:     "needs_review",
			Severity:   "medium",
			Confidence: "low",
			Summary:    "Evidence requires review.",
		}},
	}
}

func TestFindingsValidate_AcceptsClosedContract(t *testing.T) {
	if err := validFindingsForValidation().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestFindingsValidate_RejectsInvalidWireValues(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Findings)
		want string
	}{
		{"schema", func(f *Findings) { f.SchemaVersion = "teecheck.findings.v9" }, "schema_version"},
		{"run id", func(f *Findings) { f.RunID = "" }, "run_id"},
		{"nil findings", func(f *Findings) { f.Findings = nil }, "findings"},
		{"finding id", func(f *Findings) { f.Findings[0].FindingID = "" }, "finding_id"},
		{"slice id", func(f *Findings) { f.Findings[0].SliceID = "" }, "slice_id"},
		{"status", func(f *Findings) { f.Findings[0].Status = "maybe" }, "status"},
		{"severity", func(f *Findings) { f.Findings[0].Severity = "urgent" }, "severity"},
		{"confidence", func(f *Findings) { f.Findings[0].Confidence = "very sure" }, "confidence"},
		{"summary", func(f *Findings) { f.Findings[0].Summary = "" }, "summary"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validFindingsForValidation()
			tc.edit(&got)
			err := got.Validate()
			if err == nil {
				t.Fatal("Validate returned nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestFindingsValidate_AcceptsEveryClosedEnumValue(t *testing.T) {
	statuses := []string{"no_issue_observed", "needs_review", "likely_issue", "confirmed_candidate"}
	severities := []string{"high", "medium", "low"}
	confidences := []string{"high", "medium", "low"}
	for _, status := range statuses {
		for _, severity := range severities {
			for _, confidence := range confidences {
				got := validFindingsForValidation()
				got.Findings[0].Status = status
				got.Findings[0].Severity = severity
				got.Findings[0].Confidence = confidence
				if err := got.Validate(); err != nil {
					t.Fatalf("status=%s severity=%s confidence=%s: %v", status, severity, confidence, err)
				}
			}
		}
	}
}
