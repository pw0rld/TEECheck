package investigations_test

import (
	"os"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPersist_WritesSchemaValidJSON(t *testing.T) {
	runDir := t.TempDir()
	inv := investigations.Build(investigations.WireInvestigation{TWEIDs: []string{"TWE-STATE-001"}})

	path, err := investigations.Persist(runDir, inv)
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if path != runfs.InvestigationPath(runDir, inv.InvestigationID) {
		t.Errorf("path = %q, want the canonical runfs.InvestigationPath", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}
}

func TestPersist_IsIdempotent(t *testing.T) {
	runDir := t.TempDir()
	inv := investigations.Build(investigations.WireInvestigation{TWEIDs: []string{"TWE-STATE-001"}})

	first, err := investigations.Persist(runDir, inv)
	if err != nil {
		t.Fatalf("first Persist: %v", err)
	}
	second, err := investigations.Persist(runDir, inv)
	if err != nil {
		t.Fatalf("second Persist: %v", err)
	}
	if first != second {
		t.Errorf("paths differ across calls: %q vs %q", first, second)
	}
}
