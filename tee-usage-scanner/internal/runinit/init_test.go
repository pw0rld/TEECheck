package runinit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestRunCreatesManifestAndStageDirs(t *testing.T) {
	tmp := t.TempDir()
	cfg := config.Config{
		Command:            "init-run",
		RunID:              "oasis-runtime-001",
		RepoURL:            "https://github.com/oasisprotocol/oasis-sdk",
		LocalPath:          "/tmp/oasis-sdk",
		Commit:             "8a7f441",
		Focus:              "runtime",
		OutputDir:          tmp,
		Mode:               "llm",
		Samples:            2,
		MaxCases:           24,
		LLMProvider:        "openai",
		LLMBaseURL:         "https://example.test/v1",
		LLMAPIKey:          "secret-must-not-be-persisted",
		LLMModel:           "gpt-5.6-terra",
		LLMTransport:       "responses",
		LLMReasoningEffort: "high",
		LLMTimeoutSec:      600,
		LLMMaxTokens:       32768,
		LLMTemp:            0.2,
	}

	runRoot, err := Run(cfg, time.Date(2026, 4, 1, 10, 0, 0, 0, time.FixedZone("+0800", 8*3600)))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if runRoot != filepath.Join(tmp, "oasis-runtime-001") {
		t.Fatalf("unexpected run root: %s", runRoot)
	}

	for _, rel := range []string{
		"01_profile",
		"03_cases",
		"04_expert",
		"05_challenger",
		"06_verifier",
		"07_arbiter",
		"07_arbiter/packets",
	} {
		if _, err := os.Stat(filepath.Join(runRoot, rel)); err != nil {
			t.Fatalf("expected stage dir %s: %v", rel, err)
		}
	}

	// 01_repo_map and 02_hotspots belong to the legacy scanner path, which
	// only runs when --mode is not llm. Every run on disk has been llm mode
	// and left both empty, so creating them unconditionally advertised two
	// stages that never ran.
	for _, rel := range []string{"01_repo_map", "02_hotspots"} {
		if _, err := os.Stat(filepath.Join(runRoot, rel)); err == nil {
			t.Errorf("%s must not be created: nothing in the llm path writes it", rel)
		}
	}

	data, err := os.ReadFile(filepath.Join(runRoot, "00_manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest artifacts.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if strings.Contains(string(data), "secret-must-not-be-persisted") {
		t.Fatal("manifest persisted the LLM API key")
	}
	if manifest.RunID != "oasis-runtime-001" {
		t.Fatalf("unexpected run id: %s", manifest.RunID)
	}
	if manifest.Focus != "runtime" {
		t.Fatalf("unexpected focus: %s", manifest.Focus)
	}
	if manifest.ToolVersions["go"] != runtime.Version() {
		t.Fatalf("go tool version = %q, want %q", manifest.ToolVersions["go"], runtime.Version())
	}
	if manifest.ToolVersions["teecheck"] == "harness-prototype" {
		t.Fatal("manifest retained the hard-coded prototype version")
	}
	if manifest.Build == nil || manifest.Build.GoVersion != runtime.Version() {
		t.Fatalf("build provenance = %+v", manifest.Build)
	}
	if manifest.Configuration == nil {
		t.Fatal("manifest has no resolved run configuration")
	}
	got := manifest.Configuration
	if got.LLM.Provider != "openai" || got.LLM.Model != "gpt-5.6-terra" ||
		got.LLM.Transport != "responses" || got.LLM.ReasoningEffort != "high" {
		t.Fatalf("LLM provenance = %+v", got.LLM)
	}
	if got.LLM.APIKeyPresent != true {
		t.Fatal("test setup should record that a credential was present without storing it")
	}
	if got.Samples != 2 || got.MaxCases != 24 {
		t.Fatalf("run configuration = %+v", got)
	}
}

func TestRecordToolVersion(t *testing.T) {
	tmp := t.TempDir()
	runDir, err := Run(config.Config{RunID: "run", OutputDir: tmp}, time.Now())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := RecordToolVersion(runDir, "codeql", "2.24.0"); err != nil {
		t.Fatalf("RecordToolVersion returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(runDir, "00_manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest artifacts.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if got := manifest.ToolVersions["codeql"]; got != "2.24.0" {
		t.Fatalf("codeql tool version = %q, want 2.24.0", got)
	}
}
