package runinit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

func TestRunExistingIDDoesNotOverwrite(t *testing.T) {
	cfg := config.Config{RunID: "explicit", OutputDir: t.TempDir(), Commit: "first"}
	run, err := Run(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(run, "00_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Commit = "second"
	if _, err = Run(cfg, time.Now()); err == nil {
		t.Fatal("existing run ID was accepted")
	}
	after, err := os.ReadFile(filepath.Join(run, "00_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing manifest was overwritten")
	}
}

func TestConcurrentDefaultRunsUseUniqueRepositoryNames(t *testing.T) {
	cfg := config.Config{OutputDir: t.TempDir(), RepoURL: "https://example.test/team/optee_os.git", Focus: "tee"}
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	const count = 8
	paths := make(chan string, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p, err := Run(cfg, now); paths <- p; errs <- err }()
	}
	wg.Wait()
	close(paths)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for p := range paths {
		if seen[p] {
			t.Fatalf("duplicate run directory: %s", p)
		}
		seen[p] = true
		if !strings.Contains(filepath.Base(p), "-optee-os-tee-") {
			t.Fatalf("repository name missing from run ID: %s", p)
		}
		var manifest artifacts.Manifest
		data, err := os.ReadFile(filepath.Join(p, "00_manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.RunID != filepath.Base(p) {
			t.Fatal("manifest run ID differs from reserved directory")
		}
	}
}

func TestRunIDMustStayInsideOutputDirectory(t *testing.T) {
	for _, id := range []string{"..", "../outside", "nested/run", "/absolute"} {
		if _, err := Run(config.Config{RunID: id, OutputDir: t.TempDir()}, time.Now()); err == nil {
			t.Fatalf("unsafe run ID accepted: %q", id)
		}
	}
}
