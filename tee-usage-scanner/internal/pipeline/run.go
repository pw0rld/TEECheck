package pipeline

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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomix"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	scanall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func Run(cfg config.Config) (runDir string, err error) {
	// === Repo Acquisition ===
	fetch, err := repofetch.Fetch(cfg.Target)
	if err != nil {
		return "", fmt.Errorf("fetch repo: %w", err)
	}
	if fetch.Cloned {
		fmt.Printf("Cloned %s to %s (commit: %s)\n", fetch.RepoURL, fetch.LocalPath, truncate(fetch.Commit, 12))
	} else {
		fmt.Printf("Using local repo at %s (commit: %s)\n", fetch.LocalPath, truncate(fetch.Commit, 12))
	}

	cfg.LocalPath = fetch.LocalPath
	cfg.Commit = fetch.Commit
	if fetch.RepoURL != "" {
		cfg.RepoURL = fetch.RepoURL
	} else {
		cfg.RepoURL = fetch.LocalPath
	}

	// === Init Run ===
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return "", fmt.Errorf("ensure knowledge layout: %w", err)
	}
	initCfg := cfg
	initCfg.Command = "init-run"
	runDir, err = runinit.Run(initCfg, time.Now())
	if err != nil {
		return "", fmt.Errorf("init run: %w", err)
	}

	stageCfg := cfg
	stageCfg.RunDir = runDir

	// Open event recorder + blob store. From this point on, agents
	// can emit typed events that downstream stats / replay / review
	// UI fold over to derive metrics. See docs/EVENT_SCHEMA.md.
	rec, err := events.NewJSONLRecorder(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		return runDir, fmt.Errorf("init events recorder: %w", err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(runDir, "blobs"))
	if err != nil {
		_ = rec.Close()
		return runDir, fmt.Errorf("init blob store: %w", err)
	}
	manifest, manifestErr := runfs.LoadManifest(runDir)
	runID := ""
	if manifestErr == nil {
		runID = manifest.RunID
	}
	_ = rec.Emit(events.RunStarted(runID, cfg.Target, cfg.Mode, cfg.Focus))
	defer func() {
		reason := "completed"
		errMsg := ""
		if err != nil {
			reason = "error"
			errMsg = err.Error()
		}
		_ = rec.Emit(events.RunCompleted(runID, reason, errMsg))
		_ = rec.Close()
	}()

	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}

	if strings.EqualFold(cfg.Mode, "llm") {
		// === Agent 1: L3 Planner ===
		fmt.Println("\n=== Planner Agent (L3) ===")
		// LocalExecutor is constructed once and shared with the
		// planner via runL3Planner. Recorder + blob store are the
		// same instances the planner uses for its in-process
		// events, so all subprocess tool_call_* events land in the
		// same events.jsonl with the same correlation ids.
		exec := &executor.LocalExecutor{Recorder: rec, Blobs: blobs}
		if err := runL3Planner(stageCfg, fetch.LocalPath, runDir, rec, blobs, exec); err != nil {
			return runDir, fmt.Errorf("L3 planner: %w", err)
		}
		if err := cases.Run(stageCfg); err != nil {
			return "", fmt.Errorf("cases: %w", err)
		}
	} else {
		// === Agent 1: Legacy Scanner ===
		fmt.Println("\n=== Scanner Agent ===")
		graphReg := scanall.NewDefaultGraphRegistry()
		graphResult, err := scanner.Scan(context.Background(), graphReg, scanner.ScanRequest{
			RepoRoot: fetch.LocalPath,
			Focus:    cfg.Focus,
			Mode:     cfg.Mode,
		})
		if err != nil {
			return "", fmt.Errorf("scan: %w", err)
		}
		graphPath := runfs.GraphPath(runDir)
		if err := runfs.WriteJSON(graphPath, graphResult); err != nil {
			return "", fmt.Errorf("write graph: %w", err)
		}
		fmt.Printf("Graph generated: %d nodes, %d edges\n", len(graphResult.Nodes), len(graphResult.Edges))
		stageCfg.GraphJSONPath = graphPath

		if err := mapper.Run(stageCfg); err != nil {
			return "", fmt.Errorf("mapper: %w", err)
		}
		if err := cases.Run(stageCfg); err != nil {
			return "", fmt.Errorf("cases: %w", err)
		}
		if repomix.Available() {
			enrichCasesWithRepomix(runDir, fetch.LocalPath)
		}
	}

	stageCfg.AgentID = "scanner-001"
	if err := expert.Run(stageCfg); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	// === Agent 2: Reviewer ===
	fmt.Println("\n=== Reviewer Agent ===")

	needsBus := strings.EqualFold(cfg.Mode, "llm")

	if needsBus {
		bus := buildPipelineBus(cfg)

		scReg := scall.NewDefaultRegistry()
		bus.Register("scanner-001", agentbus.NewToolHandler("scanner", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
			req := staticcheck.CheckRequest{
				RepoRoot: fetch.LocalPath,
				Keywords: strings.Fields(q.Question),
			}
			findings, runErr := scReg.RunAll(ctx, req)
			if runErr != nil {
				return agentbus.Response{}, runErr
			}
			var facts []string
			for _, f := range findings {
				facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
			}
			return agentbus.Response{
				QueryID:   q.QueryID,
				FromAgent: "scanner-001",
				Answer:    fmt.Sprintf("Found %d results", len(findings)),
				Facts:     facts,
			}, nil
		}))

		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	} else {
		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.Run(stageCfg); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.Run(stageCfg); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	}

	// Print summary
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err == nil {
		fmt.Printf("\n=== Complete ===\nRun: %s\nFindings: %d\n", runDir, len(findings.Findings))
		for _, f := range findings.Findings {
			fmt.Printf("  [%s] %s — %s (confidence: %s)\n", f.Severity, f.FindingID, f.Status, f.Confidence)
		}
	}

	return runDir, nil
}

func buildPipelineBus(cfg config.Config) *agentbus.Bus {
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// runL3Planner drives the L3 LLM planner against a cloned repo,
// persists its evidence bundle + rounds log, and writes a hotspot /
// repo_map shim so the downstream 4-agent chain (cases -> expert ->
// challenger -> verifier -> arbiter) consumes the planner's candidates
// unchanged.
//
// Invoked by pipeline.Run when cfg.Mode == "llm" (M4: planner is the
// default L3 entry point). The old hotspot-via-prompt interim solution
// (formerly runLLMHotspotPipeline) is superseded and deleted.
func runL3Planner(cfg config.Config, repoRoot, runDir string, rec events.Recorder, blobs *events.BlobStore, exec executor.Executor) error {
	var profile artifacts.ProjectProfile
	if err := runfs.ReadJSON(runfs.ProjectProfilePath(runDir), &profile); err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	catalogPath := filepath.Join(cfg.KnowledgeRoot, "sinks", "rust.json")
	if _, err := os.Stat(catalogPath); err != nil {
		return fmt.Errorf("sink catalog not found at %s: %w", catalogPath, err)
	}

	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	client := llm.NewClient(cfg)
	registry := actions.NewDefaultRegistryWithSinks(catalogPath)

	fmt.Printf("Registered planner actions: %v\n", registry.Names())
	fmt.Printf("Catalog: %s\n", catalogPath)

	samples := cfg.Samples
	if samples <= 0 {
		samples = 1
	}

	promptProfile := planner.PromptProfile{
		RepoURL:        manifest.RepoURL,
		Commit:         manifest.Commit,
		Focus:          cfg.Focus,
		Languages:      profile.Languages,
		FrameworkHints: profile.FrameworkHints,
	}

	var bundles []*artifacts.EvidenceBundle
	var avoid []string

	for pass := 1; pass <= samples; pass++ {
		if samples > 1 {
			fmt.Printf("\n=== Planner pass %d/%d (avoiding %d previously-covered targets) ===\n", pass, samples, len(avoid))
		}
		result := planner.Run(context.Background(), planner.RunConfig{
			RunID:         manifest.RunID,
			RepoRoot:      repoRoot,
			RunDir:        runDir,
			Profile:       promptProfile,
			Client:        client,
			Registry:      registry,
			Budget:        planner.NewDefaultBudget(),
			Temperature:   cfg.LLMTemp,
			KnowledgeRoot: cfg.KnowledgeRoot,
			AvoidPaths:    avoid,
			Events:        rec,
			Blobs:         blobs,
			Model:         cfg.LLMModel,
			Executor:      exec,
		})

		if result.Bundle != nil {
			m := result.Bundle.PlannerMeta
			fmt.Printf("[planner pass %d] termination=%s rounds=%d/%d tokens=%d wall_clock_ms=%d candidates=%d\n",
				pass, m.TerminationReason, m.RoundsUsed, m.RoundsBudget, m.TokensUsed, m.WallClockMs, len(result.Bundle.Candidates))
			for _, c := range result.Bundle.Candidates {
				fmt.Printf("  - %s [%s, %s] paths=%v\n", c.ID, c.Kind, c.Priority, c.Paths)
			}
		}
		if result.Err != nil {
			if pass == 1 {
				return fmt.Errorf("planner pass 1: %w", result.Err)
			}
			// A later pass failing is not fatal — we already have
			// earlier-pass bundles to work with.
			fmt.Fprintf(os.Stderr, "Warning: planner pass %d failed, continuing with earlier passes: %v\n", pass, result.Err)
			break
		}
		if result.Bundle == nil {
			if pass == 1 {
				return fmt.Errorf("planner pass 1 returned nil bundle")
			}
			break
		}
		bundles = append(bundles, result.Bundle)

		// Persist per-pass bundle when running multi-sample so the
		// stats collector can later replay pass-by-pass metrics.
		if samples > 1 {
			passPath := filepath.Join(runfs.PlannerDir(runDir), fmt.Sprintf("pass-%d.json", pass))
			if err := runfs.WriteJSON(passPath, result.Bundle); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to persist pass %d bundle: %v\n", pass, err)
			}
		}

		// Accumulate dedupe state for the next pass's avoid list.
		merged := DedupeCandidates(bundles)
		avoid = AvoidList(merged)
		if samples > 1 && len(result.Bundle.Candidates) > 0 && len(merged) == accumulatedLen(bundles[:len(bundles)-1]) {
			fmt.Printf("[planner pass %d] all candidates were duplicates of earlier passes — stopping early\n", pass)
			break
		}
	}

	if len(bundles) == 0 {
		return fmt.Errorf("planner produced no bundles; check rounds.jsonl at %s", runfs.RoundsLogPath(runDir))
	}

	// Merge into a single bundle for downstream: the first bundle's
	// metadata (commit, repo, run_id) stays authoritative, candidates
	// are the deduped union.
	merged := *bundles[0]
	merged.Candidates = DedupeCandidates(bundles)
	mergedTokens := 0
	mergedWall := int64(0)
	mergedRounds := 0
	for _, b := range bundles {
		mergedTokens += b.PlannerMeta.TokensUsed
		mergedWall += b.PlannerMeta.WallClockMs
		mergedRounds += b.PlannerMeta.RoundsUsed
	}
	merged.PlannerMeta.TokensUsed = mergedTokens
	merged.PlannerMeta.WallClockMs = mergedWall
	merged.PlannerMeta.RoundsUsed = mergedRounds

	if samples > 1 {
		fmt.Printf("\n=== Multi-sample dedupe ===\n")
		rawTotal := 0
		for _, b := range bundles {
			rawTotal += len(b.Candidates)
		}
		fmt.Printf("Total raw candidates across %d passes: %d\n", len(bundles), rawTotal)
		fmt.Printf("Unique after dedup: %d\n", len(merged.Candidates))
	}

	if len(merged.Candidates) == 0 {
		return fmt.Errorf("planner produced 0 candidates after dedup; check rounds.jsonl at %s", runfs.RoundsLogPath(runDir))
	}

	// Persist merged bundle to the canonical evidence_bundle.json
	// path so downstream (and stats) see a single view of truth.
	if err := runfs.WriteJSON(runfs.EvidenceBundlePath(runDir), merged); err != nil {
		return fmt.Errorf("write merged evidence bundle: %w", err)
	}

	// Convert merged evidence_bundle candidates into the legacy
	// HotspotIndex + RepoMap shapes the downstream pipeline expects.
	return planner.WriteHotspotShim(cfg, &merged)
}

// accumulatedLen returns how many unique candidates the dedupe
// result would have had at a given list of prior bundles. Used to
// detect "this pass added nothing new so stop".
func accumulatedLen(bundles []*artifacts.EvidenceBundle) int {
	return len(DedupeCandidates(bundles))
}

func enrichCasesWithRepomix(runDir, repoRoot string) {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil || len(casePaths) == 0 {
		return
	}

	for _, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			continue
		}
		if len(pack.TargetFiles) == 0 {
			continue
		}

		result, err := repomix.Pack(context.Background(), repomix.PackRequest{
			RepoRoot:    repoRoot,
			TargetFiles: pack.TargetFiles,
			Compress:    true,
		})
		if err != nil {
			fmt.Printf("Warning: repomix failed for %s: %v\n", pack.CaseID, err)
			continue
		}

		// Add repomix content as snippets
		for path, content := range result.Files {
			if content == "" {
				continue
			}
			pack.Snippets = append(pack.Snippets, artifacts.PromptSnippet{
				Path:      path,
				StartLine: 1,
				EndLine:   strings.Count(content, "\n") + 1,
				Content:   content,
			})
		}

		if err := runfs.WriteJSON(casePath, pack); err != nil {
			fmt.Printf("Warning: failed to update case %s: %v\n", pack.CaseID, err)
		}
	}
	fmt.Printf("Enriched %d case pack(s) with Repomix compressed code context\n", len(casePaths))
}
