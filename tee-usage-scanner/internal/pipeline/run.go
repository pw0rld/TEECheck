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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/architecture"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/invariants"
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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twecontext"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

// resolveRepoIdentity decides which (repository, commit) the run is about.
// An explicitly supplied value always wins over what git reports for the
// scanned directory: a benchmark fixture is a subtree of THIS repository, so
// git would otherwise label every fixture with TEECheck's own origin and
// HEAD — and everything keyed on that pair (the TrustIR known fact tables,
// the deterministic fact IDs) would resolve against the wrong project.
// Detected values fill in whatever was left blank; the local path is the
// last-resort repository label so the field is never empty.
func resolveRepoIdentity(cfg config.Config, fetch repofetch.FetchResult) (repoURL, commit string) {
	repoURL = cfg.RepoURL
	if repoURL == "" {
		repoURL = fetch.RepoURL
	}
	if repoURL == "" {
		repoURL = fetch.LocalPath
	}
	commit = cfg.Commit
	if commit == "" {
		commit = fetch.Commit
	}
	return repoURL, commit
}

func Run(cfg config.Config) (string, error) {
	return RunWithClient(cfg, llm.NewClient(cfg))
}

func RunWithClient(cfg config.Config, client llm.Client) (runDir string, err error) {
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
	cfg.RepoURL, cfg.Commit = resolveRepoIdentity(cfg, fetch)

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

	// forAgent wraps the injected client so every Generate call a stage
	// makes leaves an llm_call_started / llm_call_completed pair in
	// events.jsonl, with the full prompt and response bodies in blobs/.
	//
	// This is the wiring seam: agents receive their llm.Client by
	// injection and llm.Client has a single method, so decorating the
	// client here instruments all of them without touching a single
	// Generate call site. Before this, only the planner recorded
	// anything, and a stage that died on a malformed reply left nothing
	// but a truncated excerpt inside an error string.
	//
	// The planner is deliberately NOT wrapped below — see runL3Planner's
	// call site.
	forAgent := func(agentID string) llm.Client {
		return llm.NewRecordingClient(client, llm.RecordingOptions{
			RunID:   runID,
			AgentID: agentID,
			Model:   cfg.LLMModel,
			Blobs:   blobs,
			Events:  rec,
		})
	}

	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}

	// Project Understanding Layer (§3.4): the Architecture model and Project
	// Invariants, derived once here and reused by the planner and agents
	// downstream. Hard-wired for now to surface any failure loudly;
	// container cases (empty knowledge root, a non-TEE repo) are exercised
	// by TestPipelineEndToEnd_FakeClient.
	//
	// client is the injected llm.Client, reused by every agent stage
	// (architecture/invariants/expert/... ) rather than each stage
	// constructing its own. Run() supplies the production client via
	// RunWithClient; tests inject a fake.
	if err := architecture.Run(stageCfg, forAgent("architecture-001")); err != nil {
		return runDir, fmt.Errorf("architecture: %w", err)
	}
	if err := invariants.Run(stageCfg, forAgent("invariants-001")); err != nil {
		return runDir, fmt.Errorf("invariants: %w", err)
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
		// The planner gets the RAW client, not forAgent(...): it already
		// emits its own llm_call_started/completed pair and writes its
		// own prompt/response blobs, and its events carry a real Round
		// number the decorator cannot know. Wrapping it would duplicate
		// every planner event and every planner blob reference.
		if err := runL3Planner(stageCfg, client, fetch.LocalPath, runDir, rec, blobs, exec); err != nil {
			return runDir, fmt.Errorf("L3 planner: %w", err)
		}
		if err := cases.Enrich(stageCfg); err != nil {
			return runDir, fmt.Errorf("cases enrich: %w", err)
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

	// Agent role identities (V1.1.2 polish C4): each stage's
	// AgentID now reflects its ROLE (expert / challenger /
	// verifier / arbiter) rather than the bus tool identity it
	// happens to run alongside (scanner / reviewer / auditor).
	// claim_emitted events and persisted agent_id fields now
	// carry the correct semantic label, which downstream consumers
	// (stats, replay, review UI) can pattern-match on.
	stageCfg.AgentID = "expert-001"
	if err := expert.RunWithEvents(stageCfg, forAgent(stageCfg.AgentID), rec, blobs); err != nil {
		return runDir, fmt.Errorf("expert: %w", err)
	}

	// === Agent 2: Reviewer ===
	fmt.Println("\n=== Reviewer Agent ===")

	bus := buildPipelineBus(cfg, forAgent)

	// Bus tool registrations stay under TOOL identities; they
	// represent capability endpoints (a static-check tool, a
	// reviewer tool, an auditor tool), not agent roles. Other
	// agents call into these tools via the bus by name.
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

	stageCfg.AgentID = "challenger-001"
	if err := challenger.RunWithEvents(stageCfg, forAgent(stageCfg.AgentID), rec); err != nil {
		return runDir, fmt.Errorf("challenger: %w", err)
	}
	stageCfg.AgentID = "verifier-001"
	if err := verifier.RunWithBusAndEvents(stageCfg, forAgent(stageCfg.AgentID), bus, rec); err != nil {
		return runDir, fmt.Errorf("verifier: %w", err)
	}

	// === Agent 3: Auditor ===
	fmt.Println("\n=== Auditor Agent ===")
	stageCfg.AgentID = "arbiter-001"
	if err := arbiter.RunWithBus(stageCfg, forAgent(stageCfg.AgentID), bus); err != nil {
		return runDir, fmt.Errorf("arbiter: %w", err)
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

// buildPipelineBus registers the bus-facing LLM handlers. forAgent yields
// the client each handler should use: a bus handler answering as
// expert-001 must record its calls under expert-001, not under whichever
// stage happened to send the query.
func buildPipelineBus(cfg config.Config, forAgent func(agentID string) llm.Client) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)

	bus.Register("expert-001", agentbus.NewLLMHandler(forAgent("expert-001"),
		"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("challenger-001", agentbus.NewLLMHandler(forAgent("challenger-001"),
		"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("reviewer-001", agentbus.NewLLMHandler(forAgent("reviewer-001"),
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

// runL3Planner drives the L3 LLM planner against a cloned repo (once per
// --samples pass), persists its evidence bundle + rounds log, and writes
// the deduped, --max-cases-capped Case Packs to 03_cases/case-*.json so the
// downstream chain (cases.Enrich -> expert -> challenger -> verifier ->
// arbiter) consumes the planner's output directly.
//
// Invoked by pipeline.Run when cfg.Mode == "llm" (M4: planner is the
// default L3 entry point). The old hotspot-via-prompt interim solution
// (formerly runLLMHotspotPipeline) is superseded and deleted.
func runL3Planner(cfg config.Config, client llm.Client, repoRoot, runDir string, rec events.Recorder, blobs *events.BlobStore, exec executor.Executor) error {
	var profile artifacts.ProjectProfile
	if err := runfs.ReadJSON(runfs.ProjectProfilePath(runDir), &profile); err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	// Wire the fact-layer action into the planner. codeql.New() resolves
	// codeql on PATH; when it is absent (the common --facts-off / no-DB
	// case) the handler fails closed per-call with unresolved, never a
	// false "no vulnerability". QueryPackDir points at the checked-in cpp
	// pack, located relative to the knowledge root's sibling — the fixed
	// TEECheck layout puts knowledge/ and codeql/ side by side. This path
	// is only consumed once a database is actually built (PR-09); until
	// then no query runs, so a wrong guess degrades to unresolved, not a
	// crash.
	eng := codeql.New()
	queryPackDir := filepath.Join(filepath.Dir(cfg.KnowledgeRoot), "codeql", "trustir", "cpp")

	// The playbook catalog backs the twe_playbook_detail action. A knowledge
	// root without a playbook directory is tolerated (preprocess applies the
	// same policy): the action then fails per call instead of the run failing.
	var playbooks actions.PlaybookDetailSource
	var tweCatalog *twecontext.Catalog
	if cat, cerr := twecontext.Load(filepath.Join(cfg.KnowledgeRoot, "twe", "playbooks")); cerr == nil {
		playbooks = cat
		tweCatalog = cat
	} else {
		fmt.Printf("Warning: TWE playbook catalog not loaded (%v); twe_playbook_detail will report no catalog\n", cerr)
	}
	registry := actions.NewDefaultRegistryWithFacts(eng, queryPackDir, playbooks)

	// Case Packs render a TWE's common_defenses / common_false_positives
	// from this map (§24) — the Challenger's phase-1 instructions rely on
	// those fields being sourced. See buildTWEPlaybookSummaries' doc
	// comment for why this conversion lives here rather than in
	// internal/planner.
	twePlaybooks := buildTWEPlaybookSummaries(tweCatalog)

	// Project Understanding artifacts produced earlier in the pipeline.
	// Read tolerantly: a run whose architecture/invariant stage produced
	// nothing still plans, just without that prior knowledge (nil model,
	// empty invariants) — the planner degrades rather than failing.
	var archPtr *artifacts.ArchitectureModel
	var archModel artifacts.ArchitectureModel
	if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &archModel); err == nil {
		archPtr = &archModel
	}
	invs, _ := runfs.ReadProjectInvariants(runDir)
	tweText, _ := os.ReadFile(runfs.TWEAgentContextPath(runDir))

	fmt.Printf("Registered planner actions: %v\n", registry.Names())

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
	var allPacks []artifacts.CasePack
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
			// Project Understanding prior knowledge (§7.5): the planner
			// investigates against these, and reaches the fact layer via
			// the fact_layer_query action registered above.
			TWEContext:   string(tweText),
			Architecture: archPtr,
			Invariants:   invs,
			// §24 Case Pack: common_defenses / common_false_positives per
			// TWE, consumed when a done.investigations entry builds a Case
			// Pack for the Challenger (internal/challenger/phase1.go).
			TWEPlaybooks: twePlaybooks,
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
		// Case Packs accumulate across passes and are deduped, capped and
		// written once after the loop. Writing per pass would renumber
		// case-*.json from 001 each time and splice the passes together.
		allPacks = append(allPacks, result.CasePacks...)

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

	// Persist merged bundle to the canonical evidence_bundle.json
	// path so downstream (and stats) see a single view of truth.
	if err := runfs.WriteJSON(runfs.EvidenceBundlePath(runDir), merged); err != nil {
		return fmt.Errorf("write merged evidence bundle: %w", err)
	}

	// Case Packs are written exactly once, here, from the union of every
	// pass. planner.Run deliberately writes nothing to 03_cases/ — it is
	// called once per --samples pass, so a per-pass write would restart the
	// case-%03d numbering each time and leave an earlier pass's
	// higher-numbered files orphaned among the current pass's.
	//
	// Dedupe first, cap second: capping a list that still holds duplicates
	// would let the same finding consume two of the --max-cases slots. The
	// legacy HotspotIndex + RepoMap shim that used to run at this point is
	// gone — downstream consumes these packs directly instead of
	// re-deriving them from a synthesized 02_hotspots/01_repo_map pair.
	final := planner.DedupePacks(allPacks)
	if cfg.MaxCases > 0 && len(final) > cfg.MaxCases {
		fmt.Printf("[planner] capping %d case packs at --max-cases=%d\n", len(final), cfg.MaxCases)
		final = final[:cfg.MaxCases]
	}
	if err := planner.Write(runDir, final); err != nil {
		return fmt.Errorf("write case packs: %w", err)
	}
	fmt.Printf("Wrote %d case pack(s) to %s\n", len(final), runfs.CasePacksDir(runDir))
	return nil
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
