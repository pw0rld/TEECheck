package repoindex

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestRun_EmptySymbolIndexIsUnavailable(t *testing.T) {
	cfg := probeRun(t, "https://example.invalid/rust-project", "abc123")
	engine := fullEngine()
	engine.rows[querySymbols] = nil
	if err := Run(cfg, readyDB{path: t.TempDir()}, engine); err != nil {
		t.Fatal(err)
	}
	facts := readFacts(t, cfg.RunDir)
	if facts.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Fatalf("zero symbols advertised as %q", facts.Capabilities.Symbols)
	}
	if len(facts.Capsules) != 0 || facts.IndexNote == "" {
		t.Fatalf("empty index did not disclose missing coverage: %+v", facts)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil || manifest.CoverageStatus != "partial" || facts.CoverageStatus != "partial" {
		t.Fatalf("missing structured partial coverage: manifest=%+v facts=%+v err=%v", manifest, facts, err)
	}
}
