package verifier

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestLoadCaseContext_IgnoresDisabledLegacyPrior(t *testing.T) {
	dir := t.TempDir()
	manifest := artifacts.Manifest{RunID: "context-test", Configuration: &artifacts.RunConfiguration{}}
	model := artifacts.ArchitectureModel{Components: []artifacts.ArchitectureElement{{ID: "old-component"}}}
	invariants := artifacts.ProjectInvariants{Invariants: []artifacts.ProjectInvariant{{InvariantID: "old-invariant"}}}
	factPath := filepath.Join(dir, "fact.json")
	for path, value := range map[string]any{
		runfs.ManifestPath(dir):          manifest,
		runfs.ArchitectureModelPath(dir): model,
		runfs.ProjectInvariantsPath(dir): invariants,
		factPath:                         artifacts.ToolFact{FactID: "current-fact"},
	} {
		if err := runfs.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	pack := artifacts.CasePack{ArchitectureRefs: []string{"old-component"}, RelatedInvariants: []string{"old-invariant"}, ToolFactRefs: []string{factPath}}
	got := loadCaseContext(dir, pack)
	if got.archModel != nil || len(got.invariants) != 0 {
		t.Fatal("disabled prior was loaded from stale artifacts")
	}
	if len(got.toolFacts) != 1 || len(got.missingToolFacts) != 0 {
		t.Fatal("disabling legacy models must preserve tool evidence")
	}
	manifest.Configuration.EnableLegacyPrior = true
	if err := runfs.WriteJSON(runfs.ManifestPath(dir), manifest); err != nil {
		t.Fatal(err)
	}
	got = loadCaseContext(dir, pack)
	if got.archModel == nil || len(got.invariants) != 1 {
		t.Fatal("explicit legacy opt-in was ignored")
	}
}
