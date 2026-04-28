package artifacts

import (
	"encoding/json"
	"testing"
)

func TestNormalizeVerdict_LegacyMapping(t *testing.T) {
	tests := []struct{ in, want string }{
		// Legacy verdicts pre-Phase 1
		{"confirmed", VerdictTruePositive},
		{"dismissed", VerdictFalsePositive},
		{"inconclusive", VerdictNeedsContext},
		// Phase 1 string that got renamed in Phase 1.5
		{"needs_more_context", VerdictNeedsContext},
		// Current vocabulary passes through
		{"true_positive", VerdictTruePositive},
		{"false_positive", VerdictFalsePositive},
		{"needs_context", VerdictNeedsContext},
		{"design_risk", VerdictDesignRisk},
		{"no_issue_observed", VerdictNoIssueObserved},
		{"skip", VerdictSkip},
		// Pass-through for extensibility
		{"unknown_value", "unknown_value"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeVerdict(tt.in); got != tt.want {
			t.Errorf("NormalizeVerdict(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestVerdictPredicates(t *testing.T) {
	t.Run("definitive", func(t *testing.T) {
		definitive := []string{VerdictTruePositive, VerdictFalsePositive,
			"confirmed", "dismissed"}
		for _, v := range definitive {
			if !IsDefinitiveVerdict(v) {
				t.Errorf("%q should be definitive", v)
			}
		}
		nonDefinitive := []string{VerdictNeedsContext, VerdictDesignRisk,
			VerdictNoIssueObserved, VerdictSkip, "needs_more_context", ""}
		for _, v := range nonDefinitive {
			if IsDefinitiveVerdict(v) {
				t.Errorf("%q should NOT be definitive", v)
			}
		}
	})
	t.Run("candidate", func(t *testing.T) {
		candidate := []string{VerdictTruePositive, VerdictFalsePositive,
			VerdictNeedsContext, VerdictDesignRisk,
			"confirmed", "dismissed", "inconclusive", "needs_more_context"}
		for _, v := range candidate {
			if !IsCandidateVerdict(v) {
				t.Errorf("%q should be candidate", v)
			}
		}
		// NIO and skip excluded — NIO is scanner self-rejection,
		// skip is reviewer abstention.
		nonCandidate := []string{VerdictNoIssueObserved, VerdictSkip, ""}
		for _, v := range nonCandidate {
			if IsCandidateVerdict(v) {
				t.Errorf("%q should NOT be candidate", v)
			}
		}
	})
}

func TestReviewRecord_RoundTripsLegacyJSON(t *testing.T) {
	// Old review-NNN.json files written before Phase 1 only had
	// Severity (not CorrectedSeverity), Verdict in legacy form,
	// no ReasonCode / ConfidenceOverride / ReviewedEvidence. Such
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
	if r.ReasonCode != "" || r.FPReason != "" || r.ConfidenceOverride != "" || r.ReviewedEvidence != nil {
		t.Errorf("Phase 1+ fields should be empty on legacy record: %+v", r)
	}
}

func TestReviewRecord_PhaseOneFPReasonReadFallback(t *testing.T) {
	// Records written by Phase 1 (8ec877e ... before Phase 1.5)
	// stored the reason in fp_reason. The new schema added
	// reason_code as the primary field; consumers must still see
	// the value via EffectiveReasonCode().
	legacy := `{
		"schema_version": "teecheck.review_record.v1",
		"case_id": "case-001",
		"finding_id": "f1",
		"verdict": "false_positive",
		"fp_reason": "wrong_layer",
		"reviewed_at": "2026-04-25T10:00:00Z"
	}`
	var r ReviewRecord
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.ReasonCode != "" {
		t.Errorf("ReasonCode should be empty when only fp_reason is set, got %q", r.ReasonCode)
	}
	if got := r.EffectiveReasonCode(); got != "wrong_layer" {
		t.Errorf("EffectiveReasonCode() = %q, want %q (fp_reason fallback)", got, "wrong_layer")
	}
}

func TestReviewRecord_NewSchemaSerializesAllFields(t *testing.T) {
	r := ReviewRecord{
		SchemaVersion:      "teecheck.review_record.v1",
		CaseID:             "case-001",
		FindingID:          "f1",
		Verdict:            VerdictFalsePositive,
		ReasonCode:         ReasonOuterValidationMissed,
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
		`"reason_code":"outer_validation_missed"`,
		`"corrected_severity":"low"`,
		`"confidence_override":"high"`,
		`"reviewed_evidence":["evidence item 1","[unanchored] tool hit"]`,
	} {
		if !contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	// New writes do NOT emit fp_reason — the legacy field stays
	// off the wire unless an old record set it directly.
	if contains(string(body), `"fp_reason"`) {
		t.Errorf("new write emitted legacy fp_reason field:\n%s", body)
	}
	// EffectiveReasonCode prefers the new field.
	if got := r.EffectiveReasonCode(); got != ReasonOuterValidationMissed {
		t.Errorf("EffectiveReasonCode() = %q, want %q", got, ReasonOuterValidationMissed)
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
