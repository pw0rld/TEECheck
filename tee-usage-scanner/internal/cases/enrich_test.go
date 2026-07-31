package cases

import (
	"os"
	"path/filepath"
	"reflect"
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

	// Every field a Case Pack can carry out of the planner is populated, so
	// the DeepEqual below fails if Enrich clears, reorders or rewrites any
	// one of them — not just the handful a field-by-field assertion happened
	// to name.
	before := artifacts.CasePack{
		SchemaVersion:        "teecheck.case_pack.v1",
		CaseID:               "inv-1",
		HotspotID:            "hotspot-1",
		Focus:                "tee",
		Category:             "state_machine",
		Priority:             "high",
		TargetFiles:          []string{"src/a.c"},
		TargetSymbols:        []string{"f"},
		WhySelected:          []string{"reached from an untrusted entrypoint"},
		ToolFacts:            []string{"legacy free-text fact"},
		GraphFacts:           []string{"caller -> callee"},
		ExpectedObligations:  []string{"freshness"},
		OpenQuestions:        []string{"is the nonce bound?"},
		RelatedTWEs:          []string{"TWE-STATE-001"},
		RelatedInvariants:    []string{"INV-STATE-001"},
		ArchitectureRefs:     []string{"comp:ta-loader"},
		ToolFactRefs:         []string{"05_facts/fact-001.json"},
		RequiredEvidence:     []string{"e"},
		MissingLinks:         []string{"version_propagated_to_authority"},
		CommonDefenses:       []string{"d"},
		CommonFalsePositives: []string{"fp"},
		CoverageGaps:         []string{"gap"},
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
	// Positive half: Enrich exists to add snippets, so it must have.
	if len(after.Snippets) == 0 {
		t.Fatal("Enrich must add snippets for the target files")
	}

	// Negative half: Snippets and KnowledgeHints are the ONLY two fields
	// Enrich is allowed to touch. Zeroing them must leave the pack
	// byte-identical to what the planner wrote. Asserting on the whole
	// struct rather than a named subset means a field added to CasePack
	// later is covered the day it is added — the field-by-field version
	// this replaced checked 4 of 22 and stayed green when Enrich was
	// mutated to clear RelatedTWEs, CommonFalsePositives, Category and
	// CoverageGaps.
	after.Snippets = nil
	after.KnowledgeHints = nil
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("Enrich must not disturb any field other than Snippets/KnowledgeHints:\n got  %+v\n want %+v", after, before)
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
