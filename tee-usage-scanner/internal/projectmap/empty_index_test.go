package projectmap

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func TestRun_NoFunctionCardsDowngradesSymbolCapability(t *testing.T) {
	cfg := probeRun(t, map[string]string{"src/lib.rs": "pub fn verify() {}\n"}, artifacts.RepoFacts{
		Capabilities: artifacts.IndexCapabilities{
			Symbols: artifacts.CapabilityAvailable, DirectCalls: artifacts.CapabilityAvailable,
			FieldAccesses: artifacts.CapabilityPartial, BuildReachability: artifacts.CapabilityUnavailable,
		},
		Languages: []string{"rust"},
	})
	if err := Run(cfg); err != nil {
		t.Fatal(err)
	}
	m := readMap(t, cfg.RunDir)
	if m.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Fatalf("zero function cards advertised as %q", m.Capabilities.Symbols)
	}
	if m.CoverageStatus != "partial" {
		t.Fatalf("missing partial coverage status: %+v", m)
	}
}
