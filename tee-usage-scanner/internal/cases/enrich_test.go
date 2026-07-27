package cases

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestEnrich_AddsSnippetsAndLeavesEverythingElseAlone(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "src", "a.c"), []byte("int f(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{LocalPath: repoRoot, Focus: "tee"}); err != nil {
		t.Fatal(err)
	}

	before := artifacts.CasePack{
		SchemaVersion:    "teecheck.case_pack.v1",
		CaseID:           "inv-1",
		TargetFiles:      []string{"src/a.c"},
		TargetSymbols:    []string{"f"},
		CommonDefenses:   []string{"d"},
		RequiredEvidence: []string{"e"},
	}
	packPath := filepath.Join(runfs.CasePacksDir(runDir), "case-001.json")
	if err := runfs.WriteJSON(packPath, before); err != nil {
		t.Fatal(err)
	}

	knowledgeRoot := t.TempDir()
	if err := Enrich(config.Config{RunDir: runDir, KnowledgeRoot: knowledgeRoot}); err != nil {
		t.Fatal(err)
	}

	var after artifacts.CasePack
	if err := runfs.ReadJSON(packPath, &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Snippets) == 0 {
		t.Fatal("Enrich must add snippets for the target files")
	}
	if after.CaseID != before.CaseID ||
		len(after.CommonDefenses) != 1 ||
		len(after.RequiredEvidence) != 1 ||
		len(after.TargetFiles) != 1 {
		t.Fatalf("Enrich must not disturb any other field: %+v", after)
	}
}

func TestEnrich_NoPacksIsNotAnError(t *testing.T) {
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{LocalPath: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := Enrich(config.Config{RunDir: runDir, KnowledgeRoot: t.TempDir()}); err != nil {
		t.Fatalf("a run with zero packs must not fail the pipeline: %v", err)
	}
}
