package arbiter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
)

func TestRunWithBus_EmptyFindingsSerializesArray(t *testing.T) {
	cfg := config.Config{
		RunID:     "empty-findings",
		OutputDir: t.TempDir(),
		RepoURL:   "https://example.test/repo",
		Commit:    "abc123",
		Focus:     "tee",
	}
	runDir, err := runinit.Run(cfg, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("init run: %v", err)
	}
	cfg.RunDir = runDir

	if err := RunWithBus(cfg, nil, nil); err != nil {
		t.Fatalf("RunWithBus: %v", err)
	}
	data, err := os.ReadFile(runfs.ArbiterFindingsPath(runDir))
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	var got artifacts.Findings
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if got.Findings == nil {
		t.Fatalf("findings decoded as nil; wire contract requires []")
	}
	if len(got.Findings) != 0 {
		t.Fatalf("findings length = %d, want 0", len(got.Findings))
	}
}

func TestRunWithBus_RejectsInvalidFindingEnums(t *testing.T) {
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "invalid-enum", LocalPath: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	pack := artifacts.CasePack{SchemaVersion: "teecheck.case_pack.v1", CaseID: "case-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), artifacts.Hypothesis{CaseID: pack.CaseID}); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), artifacts.Challenge{CaseID: pack.CaseID}); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.VerifierDir(runDir), "verify-001.json"), artifacts.VerificationMemo{CaseID: pack.CaseID}); err != nil {
		t.Fatal(err)
	}
	client := &llmtest.FakeClient{Responses: []string{`{
		"status":"invented_status","severity":"medium","confidence":"low",
		"summary":"model returned an invalid enum","evidence":[],"queries":[]
	}`}}
	err := RunWithBus(config.Config{RunDir: runDir, AgentID: "arbiter-001"}, client, agentbus.New(0))
	if err == nil {
		t.Fatal("RunWithBus returned nil")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Fatalf("error %q does not identify invalid status", err)
	}
	if _, statErr := os.Stat(runfs.ArbiterFindingsPath(runDir)); !os.IsNotExist(statErr) {
		t.Fatalf("invalid findings artifact was written: stat error=%v", statErr)
	}
}
