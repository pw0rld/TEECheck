package artifacts

// Backward-compatibility tests for the pre-merge shapes named in PR-01's
// acceptance criteria: "旧 ProjectProfile/Findings/ReviewRecord fixture 仍可
// 读取" (old ProjectProfile/Findings/ReviewRecord fixtures must still
// parse). ReviewRecord's legacy-shape coverage already lives in
// review_test.go (TestReviewRecord_RoundTripsLegacyJSON and
// TestReviewRecord_PhaseOneFPReasonReadFallback); this file covers
// ProjectProfile and Findings using real pre-merge artifacts rather than
// invented ones — testdata/legacy/*.json are unmodified copies of
// examples/oasis-sdk-scan/01_profile/project_profile.json and
// .../07_arbiter/findings.json, an actual run predating ProjectProfileV2 and
// UnifiedFindingV3.

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLegacyProjectProfileStillParses(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy/project_profile.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile ProjectProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("legacy ProjectProfile fixture failed to parse: %v", err)
	}
	if profile.SchemaVersion != "teecheck.project_profile.v1" {
		t.Errorf("schema_version = %q, want teecheck.project_profile.v1", profile.SchemaVersion)
	}
	if profile.RunID == "" {
		t.Error("run_id should not be empty")
	}
	if profile.Repo.URL == "" || profile.Repo.Commit == "" {
		t.Errorf("repo should be fully populated, got %+v", profile.Repo)
	}
	if len(profile.Languages) == 0 {
		t.Error("languages should not be empty")
	}
	if len(profile.SensitivePaths) == 0 {
		t.Error("sensitive_paths should not be empty")
	}
	// ProjectProfileV2-only concepts (tee_platforms, candidate_roles,
	// build_systems, ...) simply do not exist in the v1 shape; decoding
	// must not error just because the newer contract added fields.
}

func TestLegacyFindingsStillParses(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy/findings.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var findings Findings
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("legacy Findings fixture failed to parse: %v", err)
	}
	if findings.SchemaVersion != "teecheck.findings.v2" {
		t.Errorf("schema_version = %q, want teecheck.findings.v2", findings.SchemaVersion)
	}
	if len(findings.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings.Findings {
		if f.FindingID == "" || f.Status == "" || f.Summary == "" {
			t.Errorf("finding missing required legacy fields: %+v", f)
		}
	}
	// This fixture predates FindingItem.Locations (structured file/line);
	// it must still decode with Locations left nil rather than erroring.
	if findings.Findings[0].Locations != nil {
		t.Errorf("fixture predates structured Locations; want nil, got %+v", findings.Findings[0].Locations)
	}
}
