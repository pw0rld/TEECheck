package artifacts

import (
	"encoding/json"
	"testing"
)

func TestNormalizeVerdict_LegacyMapping(t *testing.T) {
	tests := []struct{ in, want string }{
		{"confirmed", VerdictTruePositive},
		{"dismissed", VerdictFalsePositive},
		{"inconclusive", VerdictNeedsMoreContext},
		{"true_positive", VerdictTruePositive},
		{"false_positive", VerdictFalsePositive},
		{"needs_more_context", VerdictNeedsMoreContext},
		{"skip", VerdictSkip},
		{"unknown_value", "unknown_value"}, // pass-through for extensibility
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeVerdict(tt.in); got != tt.want {
			t.Errorf("NormalizeVerdict(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReviewRecord_RoundTripsLegacyJSON(t *testing.T) {
	// Old review-NNN.json files written before Phase 1 only had
	// Severity (not CorrectedSeverity), Verdict in legacy form,
	// no FPReason / ConfidenceOverride / ReviewedEvidence. Such
	// records must continue to unmarshal cleanly.
	legacy := `{
		"schema_version": "teecheck.review_record.v1",
		"case_id": "case-001",
		"finding_id": "f1",
		"verdict": "dismissed",
		"severity": "low",
		"tags": ["fp"],
		"notes": "not a real bug",
		"reviewer_id": "alice",
		"reviewed_at": "2026-04-25T10:00:00Z"
	}`
	var r ReviewRecord
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Verdict != "dismissed" {
		t.Errorf("Verdict raw=%q (NormalizeVerdict applied at consumer level)", r.Verdict)
	}
	if NormalizeVerdict(r.Verdict) != VerdictFalsePositive {
		t.Errorf("NormalizeVerdict(%q) should produce false_positive", r.Verdict)
	}
	if r.Severity != "low" {
		t.Errorf("Severity=%q want low (legacy field preserved)", r.Severity)
	}
	if r.CorrectedSeverity != "" {
		t.Errorf("CorrectedSeverity should be empty for legacy record, got %q", r.CorrectedSeverity)
	}
	if r.FPReason != "" || r.ConfidenceOverride != "" || r.ReviewedEvidence != nil {
		t.Errorf("Phase 1 fields should be empty on legacy record: %+v", r)
	}
}

func TestReviewRecord_NewSchemaSerializesAllFields(t *testing.T) {
	r := ReviewRecord{
		SchemaVersion:      "teecheck.review_record.v1",
		CaseID:             "case-001",
		FindingID:          "f1",
		Verdict:            VerdictFalsePositive,
		FPReason:           FPWrongLayer,
		CorrectedSeverity:  "low",
		ConfidenceOverride: "high",
		ReviewedEvidence:   []string{"evidence item 1", "[unanchored] tool hit"},
		Tags:               []string{"fp"},
		Notes:              "policy is enforced one layer up",
		ReviewerID:         "alice",
		ReviewedAt:         "2026-04-25T11:00:00Z",
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"verdict":"false_positive"`,
		`"fp_reason":"wrong_layer"`,
		`"corrected_severity":"low"`,
		`"confidence_override":"high"`,
		`"reviewed_evidence":["evidence item 1","[unanchored] tool hit"]`,
	} {
		if !contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
