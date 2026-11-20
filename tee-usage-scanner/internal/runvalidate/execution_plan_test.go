package runvalidate

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestRunValidate_FailsWhenExpectedStageNeverStarted(t *testing.T) {
	dir := validBundle(t)
	patchManifest(t, dir, map[string]any{"expected_stages": []string{"must-run"}, "source_scope_mode": "local_fallback"})
	assertIssue(t, Validate(dir), "expected_stage_missing")
}

func TestRunValidate_RejectsMissingSourceScopeMode(t *testing.T) {
	dir := validBundle(t)
	patchManifest(t, dir, map[string]any{"source_scope_mode": ""})
	assertIssue(t, Validate(dir), "source_scope_mode")
}

func TestRunValidate_ReportsIncompleteReconSeparately(t *testing.T) {
	dir := validBundle(t)
	if err := runfs.WriteJSON(runfs.CoverageLedgerPath(dir), map[string]any{"schema_version": "teecheck.coverage_ledger.v1", "run_id": "run-1", "by_sample": []any{map[string]any{"sample_index": 0, "recon_status": "budget_exhausted"}}}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(Validate(dir))
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if got["coverage_complete"] != false {
		t.Fatalf("incomplete reconnaissance was not reported: %s", b)
	}
}

func TestRunValidate_RequiresReviewArtifactsForSelectedCase(t *testing.T) {
	dir := validBundle(t)
	if err := runfs.WriteJSON(runfs.CasePacksDir(dir)+"/case-001.json", map[string]string{"case_id": "selected-case"}); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "case_outputs")
}

func patchManifest(t *testing.T, dir string, values map[string]any) {
	t.Helper()
	b, err := os.ReadFile(runfs.ManifestPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range values {
		m[k] = v
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(dir), m); err != nil {
		t.Fatal(err)
	}
}
