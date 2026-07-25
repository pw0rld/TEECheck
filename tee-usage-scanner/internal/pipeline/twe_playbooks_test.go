package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twecontext"
)

const testPlaybookFixture = `schema_version: teecheck.twe_playbook.v1
id: TWE-STATE-TEST
name: Test State Weakness
family: State
scenario: A replayed state changes a security decision.
attacker_capabilities: [replay_state]
look_for: [restore_path]
investigation_steps: [trace_restore]
required_evidence: [reachable_restore]
common_defenses: [monotonic_counter, signed_epoch]
common_false_positives: [cache_only]
related_twes: []
trustir_hints: [trace_restore_to_authority]
`

func TestBuildTWEPlaybookSummaries_ConvertsCatalog(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(testPlaybookFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := twecontext.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := buildTWEPlaybookSummaries(catalog)

	summary, ok := got["TWE-STATE-TEST"]
	if !ok {
		t.Fatalf("expected an entry for TWE-STATE-TEST, got %v", got)
	}
	if len(summary.CommonDefenses) != 2 || summary.CommonDefenses[0] != "monotonic_counter" || summary.CommonDefenses[1] != "signed_epoch" {
		t.Errorf("CommonDefenses = %v, want [monotonic_counter signed_epoch]", summary.CommonDefenses)
	}
	if len(summary.CommonFalsePositives) != 1 || summary.CommonFalsePositives[0] != "cache_only" {
		t.Errorf("CommonFalsePositives = %v, want [cache_only]", summary.CommonFalsePositives)
	}
}

func TestBuildTWEPlaybookSummaries_NilCatalogReturnsEmptyNotNilMap(t *testing.T) {
	got := buildTWEPlaybookSummaries(nil)
	if got == nil {
		t.Fatal("expected a non-nil empty map for a nil catalog")
	}
	if len(got) != 0 {
		t.Fatalf("expected an empty map, got %v", got)
	}
}
