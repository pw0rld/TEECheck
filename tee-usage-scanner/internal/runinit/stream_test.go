package runinit

import (
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestStreamConfigurationRecordedInManifestAndRoleSnapshots(t *testing.T) {
	cfg := config.Config{RunID: "stream-run", OutputDir: t.TempDir(), LLMStream: true, LLMProvider: "openai"}
	runDir, err := Run(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	verifier := roles["verifier"]
	verifier.LLMStream = false
	roles["verifier"] = verifier
	if err = RecordRoleConfigurations(runDir, roles); err != nil {
		t.Fatal(err)
	}
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Configuration == nil || !manifest.Configuration.LLM.Stream {
		t.Fatal("manifest lost global stream setting")
	}
	var saved struct {
		Metadata struct {
			Roles map[string]RoleLLMSnapshot `json:"role_llm"`
		} `json:"metadata"`
	}
	if err = runfs.ReadJSON(runfs.ManifestPath(runDir), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Metadata.Roles["planner"].Stream || saved.Metadata.Roles["verifier"].Stream {
		t.Fatalf("role stream settings not retained: %+v", saved.Metadata.Roles)
	}
}
