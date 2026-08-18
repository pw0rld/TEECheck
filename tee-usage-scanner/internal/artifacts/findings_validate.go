package artifacts

import (
	"fmt"
	"strings"
)

var (
	findingStatuses = map[string]struct{}{
		"no_issue_observed":   {},
		"needs_review":        {},
		"likely_issue":        {},
		"confirmed_candidate": {},
	}
	findingSeverities = map[string]struct{}{
		"high": {}, "medium": {}, "low": {},
	}
	findingConfidences = map[string]struct{}{
		"high": {}, "medium": {}, "low": {},
	}
)

// Validate rejects findings that cannot satisfy the persisted v2 contract.
// It runs after model output is normalized and before the artifact is written.
func (f Findings) Validate() error {
	if f.SchemaVersion != "teecheck.findings.v2" {
		return fmt.Errorf("schema_version must be teecheck.findings.v2, got %q", f.SchemaVersion)
	}
	if strings.TrimSpace(f.RunID) == "" {
		return fmt.Errorf("run_id is required")
	}
	if f.Findings == nil {
		return fmt.Errorf("findings must be an array, not null")
	}
	for i, item := range f.Findings {
		prefix := fmt.Sprintf("findings[%d]", i)
		if strings.TrimSpace(item.FindingID) == "" {
			return fmt.Errorf("%s.finding_id is required", prefix)
		}
		if strings.TrimSpace(item.SliceID) == "" {
			return fmt.Errorf("%s.slice_id is required", prefix)
		}
		if _, ok := findingStatuses[item.Status]; !ok {
			return fmt.Errorf("%s.status has unsupported value %q", prefix, item.Status)
		}
		if _, ok := findingSeverities[item.Severity]; !ok {
			return fmt.Errorf("%s.severity has unsupported value %q", prefix, item.Severity)
		}
		if _, ok := findingConfidences[item.Confidence]; !ok {
			return fmt.Errorf("%s.confidence has unsupported value %q", prefix, item.Confidence)
		}
		if strings.TrimSpace(item.Summary) == "" {
			return fmt.Errorf("%s.summary is required", prefix)
		}
	}
	return nil
}
