package artifacts

import "testing"

// EffectiveSeverity is the single place the CorrectedSeverity-over-
// Severity preference documented on ReviewRecord.Severity lives, so
// no consumer can read the raw field and silently get "".
func TestReviewRecord_EffectiveSeverity(t *testing.T) {
	tests := []struct {
		name   string
		record ReviewRecord
		want   string
	}{
		{
			name:   "new write sets only CorrectedSeverity",
			record: ReviewRecord{CorrectedSeverity: "critical"},
			want:   "critical",
		},
		{
			name:   "legacy record sets only Severity",
			record: ReviewRecord{Severity: "medium"},
			want:   "medium",
		},
		{
			name:   "both present prefers the human correction",
			record: ReviewRecord{CorrectedSeverity: "low", Severity: "high"},
			want:   "low",
		},
		{
			name:   "neither present",
			record: ReviewRecord{},
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.record.EffectiveSeverity(); got != tc.want {
				t.Errorf("EffectiveSeverity() = %q, want %q", got, tc.want)
			}
		})
	}
}
