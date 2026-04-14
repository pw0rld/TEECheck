package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

// runPlanCommand is the CLI entry point for the L3 LLM planner.
// It bypasses the existing mapper/hotspots/cases/expert/challenger/
// verifier/arbiter pipeline and directly drives planner.Run.
//
// Flow:
//  1. Resolve target (clone URL or use local path)
//  2. Create run directory + manifest + profile
//  3. Build llm.Client and actions.Registry
//  4. Call planner.Run
//  5. Print summary
func runPlanCommand(cfg config.Config) error {
	now := time.Now()

	fetch, err := repofetch.Fetch(cfg.Target)
	if err != nil {
		return fmt.Errorf("fetch target: %w", err)
	}
	fmt.Printf("Using repo at %s (commit: %s)\n", fetch.LocalPath, shortCommit(fetch.Commit))

	cfg.RepoURL = fetch.RepoURL
	cfg.LocalPath = fetch.LocalPath
	cfg.Commit = fetch.Commit

	runRoot, err := runinit.Run(cfg, now)
	if err != nil {
		return fmt.Errorf("init run: %w", err)
	}
	cfg.RunDir = runRoot
	fmt.Printf("Run directory: %s\n", runRoot)

	if err := preprocessor.Run(cfg); err != nil {
		return fmt.Errorf("preprocess: %w", err)
	}

	var profile artifacts.ProjectProfile
	if err := runfs.ReadJSON(runfs.ProjectProfilePath(cfg.RunDir), &profile); err != nil {
		return fmt.Errorf("read profile: %w", err)
	}

	client := llm.NewClient(cfg)
	catalogPath := filepath.Join(cfg.KnowledgeRoot, "sinks", "rust.json")
	if _, err := os.Stat(catalogPath); err != nil {
		return fmt.Errorf("sink catalog not found at %s: %w", catalogPath, err)
	}
	registry := actions.NewDefaultRegistryWithSinks(catalogPath)

	fmt.Printf("Registered actions: %v\n", registry.Names())
	fmt.Printf("Catalog: %s\n", catalogPath)

	runID := filepath.Base(runRoot)
	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    runID,
		RepoRoot: fetch.LocalPath,
		RunDir:   runRoot,
		Profile: planner.PromptProfile{
			RepoURL:        fetch.RepoURL,
			Commit:         fetch.Commit,
			Focus:          cfg.Focus,
			Languages:      profile.Languages,
			FrameworkHints: profile.FrameworkHints,
		},
		Client:      client,
		Registry:    registry,
		Budget:      planner.NewDefaultBudget(),
		Temperature: cfg.LLMTemp,
	})

	if result.Bundle == nil {
		return result.Err
	}
	m := result.Bundle.PlannerMeta
	fmt.Printf("\n=== Planner Result ===\n")
	fmt.Printf("Termination: %s\n", m.TerminationReason)
	fmt.Printf("Rounds: %d/%d\n", m.RoundsUsed, m.RoundsBudget)
	fmt.Printf("Tokens: %d\n", m.TokensUsed)
	fmt.Printf("Wall clock: %dms\n", m.WallClockMs)
	fmt.Printf("Candidates: %d\n", len(result.Bundle.Candidates))
	for _, c := range result.Bundle.Candidates {
		fmt.Printf("  - %s [%s, %s] paths=%v\n", c.ID, c.Kind, c.Priority, c.Paths)
	}
	if result.Bundle.FinalSummary != "" {
		fmt.Printf("\nSummary: %s\n", result.Bundle.FinalSummary)
	}

	if result.Err != nil {
		fmt.Printf("\n⚠  Planner ended with error: %v\n", result.Err)
		fmt.Printf("   Skipping downstream audit stages.\n")
		return result.Err
	}
	if len(result.Bundle.Candidates) == 0 {
		fmt.Printf("\nNo candidates to audit. Skipping downstream agents.\n")
		return nil
	}

	// ─── Hand off to the existing 4-agent audit pipeline ───
	//
	// The L3 planner's candidates become the input to cases / expert /
	// challenger / verifier / arbiter, just like the legacy
	// hotspot_index would. We synthesize a hotspot_index shim from the
	// candidates so downstream code reads it unchanged.
	if err := writeHotspotShim(cfg, result.Bundle); err != nil {
		return fmt.Errorf("write hotspot shim: %w", err)
	}

	// Build an agent bus for verifier + arbiter. These two agents
	// branch on (cfg.Mode, bus presence) — verifier.Run and
	// arbiter.Run are HEURISTIC-only fallbacks, the LLM path is in
	// verifier.RunWithBus and arbiter.RunWithBus. Without the bus
	// the verifier just runs grep and emits "inconclusive" for every
	// case, which is exactly what we saw in v10–v12.
	bus := buildPlannerBus(cfg)

	busStages := []struct {
		name string
		fn   func(config.Config) error
	}{
		{"cases", cases.Run},
		{"expert", expert.Run},
		{"challenger", challenger.Run},
		{"verifier", func(c config.Config) error { return verifier.RunWithBus(c, bus) }},
		{"arbiter", func(c config.Config) error { return arbiter.RunWithBus(c, bus) }},
	}
	for _, s := range busStages {
		fmt.Printf("\n=== %s ===\n", s.name)
		if err := s.fn(cfg); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	// ─── Final summary: point at arbiter packets ───
	packetsDir := runfs.ArbiterPacketsDir(cfg.RunDir)
	entries, _ := os.ReadDir(packetsDir)
	var packets []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			packets = append(packets, filepath.Join(packetsDir, e.Name()))
		}
	}
	fmt.Printf("\n=== Audit Complete ===\n")
	fmt.Printf("Review packets (%d):\n", len(packets))
	for _, p := range packets {
		fmt.Printf("  %s\n", p)
	}
	findingsPath := runfs.ArbiterFindingsPath(cfg.RunDir)
	if _, err := os.Stat(findingsPath); err == nil {
		fmt.Printf("\nFinal findings: %s\n", findingsPath)
	}
	return nil
}

// writeHotspotShim converts a planner evidence bundle's candidates
// into the legacy HotspotIndex shape so cases.Run (and downstream)
// can consume it unchanged. It also writes a minimal repo_map shim
// because cases.Run requires repo_map.json to exist (the planner
// skips the mapper stage that would normally produce it).
//
// This is the bridge between the L3 planner output and the existing
// 4-agent audit pipeline.
func writeHotspotShim(cfg config.Config, bundle *artifacts.EvidenceBundle) error {
	hotspots := make([]artifacts.Hotspot, 0, len(bundle.Candidates))
	for i, c := range bundle.Candidates {
		hid := c.ID
		if hid == "" {
			hid = fmt.Sprintf("hotspot-%03d", i+1)
		}
		hotspots = append(hotspots, artifacts.Hotspot{
			HotspotID:   hid,
			Kind:        c.Kind,
			Priority:    c.Priority,
			Paths:       c.Paths,
			Symbols:     c.Symbols,
			WhySelected: c.WhySelected,
		})
	}
	index := artifacts.HotspotIndex{
		SchemaVersion: "teecheck.hotspot_index.v1",
		RunID:         bundle.RunID,
		Hotspots:      hotspots,
	}
	if err := runfs.WriteJSON(runfs.HotspotIndexPath(cfg.RunDir), index); err != nil {
		return err
	}

	// Minimal repo_map shim. cases.Run only uses repoMap.Boundaries
	// for collectToolFacts enrichment; an empty Boundaries slice means
	// that enrichment silently no-ops, which is fine for v1.
	repoMap := artifacts.RepoMap{
		SchemaVersion: "teecheck.repo_map.v1",
		Repo:          bundle.Repo,
	}
	return runfs.WriteJSON(runfs.RepoMapPath(cfg.RunDir), repoMap)
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// buildPlannerBus constructs the inter-agent message bus that the
// LLM paths of verifier and arbiter require. It mirrors the bus
// that pipeline.Run builds, with the same three handlers so
// downstream agents can query expert / challenger / reviewer.
func buildPlannerBus(cfg config.Config) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)
	client := llm.NewClient(cfg)
	bus.Register("expert-001", agentbus.NewLLMHandler(client,
		"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("challenger-001", agentbus.NewLLMHandler(client,
		"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("reviewer-001", agentbus.NewLLMHandler(client,
		"You are the Reviewer Agent in TEECheck. Another agent asks you about your verification. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	return bus
}
