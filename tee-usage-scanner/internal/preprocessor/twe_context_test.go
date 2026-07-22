package preprocessor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestCompileTWEKnowledgePersistsContextAndManifest(t *testing.T) {
	knowledgeRoot := t.TempDir()
	runDir := t.TempDir()
	playbooks := filepath.Join(knowledgeRoot, "twe", "playbooks")
	if err := os.MkdirAll(playbooks, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, playbooks, "test.yml", validTWEContextFixture)

	written, err := compileTWEKnowledge(knowledgeRoot, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !written {
		t.Fatal("compileTWEKnowledge reported no output")
	}
	contextBytes, err := os.ReadFile(runfs.TWEAgentContextPath(runDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contextBytes), "TWE-STATE-FIXTURE") {
		t.Fatal("compiled context does not contain fixture TWE")
	}
	var manifest artifacts.TWEKnowledgeManifest
	if err := runfs.ReadJSON(runfs.TWEKnowledgeManifestPath(runDir), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.TWEIDs) != 1 || manifest.TWEIDs[0] != "TWE-STATE-FIXTURE" {
		t.Fatalf("manifest IDs = %v", manifest.TWEIDs)
	}
}

func TestCompileTWEKnowledgeAllowsLegacyRootWithoutPlaybooks(t *testing.T) {
	written, err := compileTWEKnowledge(t.TempDir(), t.TempDir())
	if err != nil || written {
		t.Fatalf("written=%v err=%v, want false, nil", written, err)
	}
}

const validTWEContextFixture = `schema_version: teecheck.twe_playbook.v1
id: TWE-STATE-FIXTURE
name: Fixture
family: State
scenario: Historical state is accepted.
attacker_capabilities: [replay_state]
look_for: [restore]
investigation_steps: [trace_restore]
required_evidence: [reachable_restore]
common_defenses: [counter]
common_false_positives: [cache_only]
related_twes: []
trustir_hints: [trace_restore]
`
