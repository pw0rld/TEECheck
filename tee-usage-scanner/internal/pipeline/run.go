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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/invariants"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/projectmap"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repoindex"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
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

// runStage brackets one pipeline stage with a stage_started /
// stage_completed pair and returns the stage's error untouched.
//
// This is the wiring seam for stage-level instrumentation, chosen for
// the same reason the LLM recording decorator wraps llm.Client: the
// pipeline already calls every stage, so wrapping the calls here
// instruments all of them — including the deterministic ones that make
// no LLM call and therefore used to leave no trace whatsoever — without
// editing a single stage package.
//
// The completed event fires on every path, failure included. A stream
// that goes silent when a stage dies is the case where the record
// matters most: it is the only thing that says which stage killed the
// run and what it said on the way out.
//
// Emission is best-effort; a recorder that cannot write must not be the
// reason a stage does not run, so a nil recorder is tolerated.
func runStage(rec events.Recorder, runID, stage string, fn func() error) error {
	if rec == nil {
		return fn()
	}
	_ = rec.Emit(events.StageStarted(runID, stage))
	start := time.Now()
	err := fn()
	reason, errMsg := "completed", ""
	if err != nil {
		reason, errMsg = "error", err.Error()
	}
	_ = rec.Emit(events.StageCompleted(runID, stage, reason, time.Since(start).Milliseconds(), errMsg))
	return err
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
	plannerBudget := planner.NewDefaultBudget()
	if err := runinit.RecordPlannerLimits(runDir, artifacts.PlannerLimits{
		MaxInvestigationRounds: plannerBudget.MaxRounds,
		MaxReconRounds:         plannerBudget.MaxReconRounds,
		MaxAggregateTokens:     plannerBudget.MaxTokens,
		ReconMaxTokens:         plannerBudget.MaxReconTokens,
		InvestigationMaxTokens: plannerBudget.MaxInvestigationTokens,
		ReserveTokensForDone:   plannerBudget.ConvergenceReserveTokens,
		PerActionTimeoutMs:     plannerBudget.PerActionTimeout.Milliseconds(),
		WallClockTimeoutMs:     plannerBudget.WallClock.Milliseconds(),
	}); err != nil {
		return runDir, fmt.Errorf("record planner limits: %w", err)
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
	_ = rec.Emit(events.RunConfig(runID, processCommand()))
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

	// stage brackets a pipeline stage with stage_started /
	// stage_completed. See runStage for why the seam lives here.
	stage := func(name string, fn func() error) error {
		return runStage(rec, runID, name, fn)
	}

	// The recording executor is constructed once and shared by every
	// subprocess-class tool in the run: the planner's own actions, the
	// semgrep adapter behind the scanner bus tool, the CodeQL fact
	// engine, the git clone the fact layer does to build a database, and
	// the repomix enrichment pass. Recorder + blob store are the same
	// instances every other emitter uses, so all tool_call_* events land
	// in the same events.jsonl under the same correlation ids.
	//
	// executor.Bind attaches the agent identity at each wiring site,
	// because the packages themselves know which command they run but not
	// which stage is running it — and a tool_call_completed that cannot
	// be traced to a stage is noise.
	exec := &executor.LocalExecutor{Recorder: rec, Blobs: blobs}

	// Acquire the tree the whole run reads, before the first stage. See
	// acquireSourceScope: every stage from here on resolves paths against
	// this one root, so the models, the tools and the fact layer describe
	// the same revision.
	// One database manager for the whole run, and two engines bound to the
	// agents whose work they do.
	//
	// Engine and provider are peer dependencies: an engine runs queries, the
	// manager owns the database's and the checkout's lifecycle. Threading
	// one manager to every consumer is what makes "built once per run" a
	// property of the wiring rather than a coincidence — before
	// internal/codedb a second consumer could only have built a second
	// database (91 seconds and 322 MB, twice) or reimplemented the path
	// derivation and drifted from it.
	//
	// The two engines differ only in which agent their subprocess events are
	// attributed to. Acquiring and extracting the repository is the index
	// stage's work; querying the fact layer is the planner's. Attributing
	// the 91-second extraction to a planner round — which is what happened
	// while the build lived in the planner's first round — makes the
	// planner's own cost unreadable.
	indexEng := codeql.New()
	indexEng.Exec = executor.Bind(exec, executor.Binding{RunID: runID, Agent: indexAgent})
	codeqlVersion := "unavailable"
	if indexEng.Available() {
		var versionErr error
		codeqlVersion, versionErr = indexEng.Version(context.Background())
		if versionErr != nil {
			codeqlVersion = "error"
		}
	}
	if err := runinit.RecordToolVersion(runDir, "codeql", codeqlVersion); err != nil {
		return runDir, fmt.Errorf("record CodeQL version: %w", err)
	}
	codeDB := codedb.New(indexEng,
		executor.Bind(exec, executor.Binding{RunID: runID, Agent: indexAgent}))

	srcRoot, pinned := acquireSourceScope(context.Background(), codeDB,
		runDir, cfg.RepoURL, cfg.Commit, fetch.LocalPath)
	scopeReason := "target directory; no pinned checkout"
	if pinned {
		scopeReason = fmt.Sprintf("pinned checkout of %s@%s", cfg.RepoURL, truncate(cfg.Commit, 12))
	}
	fmt.Printf("Source scope: %s (%s)\n", srcRoot, scopeReason)
	_ = rec.Emit(events.SourceScopeResolved(runID, srcRoot, scopeReason))
	stageCfg.LocalPath = srcRoot
	// The manifest is the run's single statement of what was scanned, and
	// most stages read the tree from it rather than from their own config:
	// preprocess walks manifest.LocalPath, and invariants, expert and
	// verifier resolve every citation against it. Leaving it at the target
	// directory while the tools read the checkout would put the two scopes
	// back — the same split as reading two different trees, only harder to see because
	// nothing would print it. runinit writes the manifest before this point
	// (the checkout needs the run directory to live in), so it is corrected
	// here rather than pre-computed.
	if err := recordScannedRoot(runDir, srcRoot); err != nil {
		return runDir, fmt.Errorf("record scanned root: %w", err)
	}

	if err := stage("preprocess", func() error { return preprocessor.Run(stageCfg) }); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}

	// 01A / 01B: the deterministic whole-repo program index, and the neutral
	// navigation view derived from it. They run before architecture because
	// architecture consumes the map, and before the planner because the
	// planner browses it.
	//
	// The CodeQL database is built here, once. It used to be built inside
	// the planner's first round: 91.6 seconds of the planner's own budget
	// spent on infrastructure, and invisible as such because it arrived as a
	// round-0 tool call.
	if err := stage("repo_index", func() error {
		return repoindex.Run(stageCfg, codeDB, indexEng)
	}); err != nil {
		return runDir, fmt.Errorf("repo index: %w", err)
	}
	if err := stage("project_map", func() error { return projectmap.Run(stageCfg) }); err != nil {
		return runDir, fmt.Errorf("project map: %w", err)
	}

	// The old pre-investigation models have no source evidence in their
	// prompts. Keep them explicitly opt-in during migration; ordinary runs
	// proceed from the program map to grounded investigation instead.
	if cfg.EnableLegacyPrior {
		if err := stage("architecture", func() error {
			return architecture.Run(stageCfg, forAgent("architecture-001"))
		}); err != nil {
			return runDir, fmt.Errorf("architecture: %w", err)
		}
		if err := stage("invariants", func() error {
			return invariants.Run(stageCfg, forAgent("invariants-001"))
		}); err != nil {
			return runDir, fmt.Errorf("invariants: %w", err)
		}
	}

	// === Agent 1: L3 Planner ===
	fmt.Println("\n=== Planner Agent (L3) ===")
	// The planner gets the RAW client, not forAgent(...): it already
	// emits its own llm_call_started/completed pair and writes its
	// own prompt/response blobs, and its events carry a real Round
	// number the decorator cannot know. Wrapping it would duplicate
	// every planner event and every planner blob reference.
	if err := stage("l3_planner", func() error {
		return runL3Planner(stageCfg, client, codeDB, srcRoot, runDir, rec, blobs, exec)
	}); err != nil {
		return runDir, fmt.Errorf("L3 planner: %w", err)
	}
	if err := stage("cases_enrich", func() error { return cases.Enrich(stageCfg) }); err != nil {
		return runDir, fmt.Errorf("cases enrich: %w", err)
	}

	// Agent role identities (V1.1.2 polish C4): each stage's
	// AgentID now reflects its ROLE (expert / challenger /
	// verifier / arbiter) rather than the bus tool identity it
	// happens to run alongside (scanner / reviewer / auditor).
	// claim_emitted events and persisted agent_id fields now
	// carry the correct semantic label, which downstream consumers
	// (stats, replay, review UI) can pattern-match on.
	stageCfg.AgentID = "expert-001"
	if err := stage("expert", func() error {
		return expert.RunWithEvents(stageCfg, forAgent(stageCfg.AgentID), rec, blobs)
	}); err != nil {
		return runDir, fmt.Errorf("expert: %w", err)
	}

	// === Agent 2: Reviewer ===
	fmt.Println("\n=== Reviewer Agent ===")

	bus := buildPipelineBus(cfg, forAgent)
	// Refused inter-agent queries become events. Without this the arbiter's
	// own stated reason for capping a finding at needs_review — "follow-up
	// queries failed (agents unavailable)" — appears nowhere in the run
	// record; it survived only inside an LLM prompt blob.
	bus.SetRecorder(rec, runID)
	// Somewhere to keep the full body of an answer the bus had to cap, so the
	// preview notice in the prompt names a location a reader can open.
	bus.SetBlobs(blobs)

	// Bus tool registrations stay under TOOL identities; they
	// represent capability endpoints (a static-check tool, a
	// reviewer tool, an auditor tool), not agent roles. Other
	// agents call into these tools via the bus by name.
	// The semgrep adapter inside this registry shells out. Binding it to
	// scanner-001 matches the bus identity the handler is registered
	// under directly below, so a semgrep tool_call lands under the same
	// agent as the query that provoked it.
	scReg := scall.NewDefaultRegistryWithExecutor(executor.Bind(exec,
		executor.Binding{RunID: runID, Agent: "scanner-001"}))
	// The CodeQL adapter needs a prebuilt database and a query set — this run
	// built one during l3_planner's fact-layer prefetch, and without wiring it
	// through, scanner-001 answered every query with "a prebuilt database is
	// required" while the database sat in the same run directory. On
	// 2026-08-01 both of the arbiter's queries to it failed that way and it
	// fell back to an agent with no tools at all.
	scannerExtra := map[string]string{}
	if db := findBuiltCodeQLDB(runDir); db != "" {
		scannerExtra["database"] = db
		scannerExtra["queries"] = filepath.Join(filepath.Dir(cfg.KnowledgeRoot), "codeql", "trustir", "cpp")
	}
	// The one tool-backed bus agent searches the same pinned checkout the
	// planner reads and the facts came from, when the fact layer produced
	// one. Pointed at the scanned directory it could only ever answer about
	// the fixture: on 2026-08-01 the verifier asked it eight times for
	// signed_hdr.h and for callers of shdr_verify_signature, and eight times
	// it returned the lines of core/crypto/signed_hdr.c — the only file it
	// could see.
	scannerRoot := srcRoot
	bus.Register("scanner-001", agentbus.NewToolHandler("scanner", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
		// Search for what the question names, not for every word in it. See
		// searchTerms: strings.Fields put "the" and "of" into the keyword
		// list, which matched most of the checkout.
		terms := searchTerms(q.Question)
		if len(terms) == 0 {
			return agentbus.Response{
				QueryID:   q.QueryID,
				FromAgent: "scanner-001",
				Answer:    noSearchableTerm,
			}, nil
		}
		req := staticcheck.CheckRequest{
			RepoRoot:  scannerRoot,
			Keywords:  terms,
			ExtraArgs: scannerExtra,
		}
		// A partial result is still a result: RunAll now reports every
		// adapter failure while keeping what the working ones found.
		findings, runErr := scReg.RunAll(ctx, req)
		if runErr != nil && len(findings) == 0 {
			return agentbus.Response{}, runErr
		}
		var facts []string
		for _, f := range findings {
			facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
		}
		answer := fmt.Sprintf("Found %d results for %s", len(findings), strings.Join(terms, ", "))
		if runErr != nil {
			answer += fmt.Sprintf(" (some adapters unavailable: %v)", runErr)
		}
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "scanner-001",
			Answer:    answer,
			Facts:     facts,
		}, nil
	}))

	stageCfg.AgentID = "challenger-001"
	if err := stage("challenger", func() error {
		return challenger.RunWithEvents(stageCfg, forAgent(stageCfg.AgentID), rec)
	}); err != nil {
		return runDir, fmt.Errorf("challenger: %w", err)
	}
	stageCfg.AgentID = "verifier-001"
	if err := stage("verifier", func() error {
		return verifier.RunWithBusAndEvents(stageCfg, forAgent(stageCfg.AgentID), bus, rec)
	}); err != nil {
		return runDir, fmt.Errorf("verifier: %w", err)
	}

	// === Agent 3: Auditor ===
	fmt.Println("\n=== Auditor Agent ===")
	stageCfg.AgentID = "arbiter-001"
	if err := stage("arbiter", func() error {
		return arbiter.RunWithBus(stageCfg, forAgent(stageCfg.AgentID), bus)
	}); err != nil {
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
// Invoked unconditionally by pipeline.Run (M4: planner is the
// default L3 entry point). The old hotspot-via-prompt interim solution
// (formerly runLLMHotspotPipeline) is superseded and deleted.
func runL3Planner(cfg config.Config, client llm.Client, db codedb.DatabaseProvider, srcRoot, runDir string, rec events.Recorder, blobs *events.BlobStore, exec executor.Executor) error {
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
	eng := newFactEngine(exec, manifest.RunID)
	queryPackDir := filepath.Join(filepath.Dir(cfg.KnowledgeRoot), "codeql", "trustir", "cpp")

	// The playbook catalog backs the twe_playbook_detail action. A knowledge
	// root without a playbook directory is tolerated (preprocess applies the
	// same policy): the action then fails per call instead of the run failing.
	var playbooks actions.PlaybookDetailSource
	var tweCatalog *twecontext.Catalog
	if cat, cerr := twecontext.Load(filepath.Join(cfg.KnowledgeRoot, "twe", "exemplars")); cerr == nil {
		playbooks = cat
		tweCatalog = cat
	} else {
		fmt.Printf("Warning: TWE playbook catalog not loaded (%v); twe_playbook_detail will report no catalog\n", cerr)
	}
	registry := actions.NewDefaultRegistryWithFacts(eng, db, queryPackDir, playbooks)

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
	var invs []artifacts.ProjectInvariant
	if cfg.EnableLegacyPrior {
		if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &archModel); err == nil {
			archPtr = &archModel
		}
		invs, _ = runfs.ReadProjectInvariants(runDir)
	}
	tweText, _ := os.ReadFile(runfs.TWEAgentContextPath(runDir))

	fmt.Printf("Registered planner actions: %v\n", registry.Names())

	// Nothing is prefetched for the planner. The pipeline used to run the
	// fact-layer queries the run's invariants called for and hand the
	// resulting refs to planner.Run, which unioned them into every
	// investigation it reported — so a lead the model reached on its own
	// still shipped evidence the old invariant had selected, and the same
	// facts were attached by path match to every Case Pack downstream.
	// An unevidenced anchor is what that chain produces. The Planner now cites only
	// what it executed itself; §6 says a lead's reasons must reference facts
	// the Planner has seen, and a prefetched fact is not one of them.

	samples := cfg.Samples
	if samples <= 0 {
		samples = 1
	}

	// The fact layer just checked out the pinned revision to build its
	// database from, and that checkout is now kept. Read the source from it.
	//
	// Until now the planner's tools resolved paths against the scanned
	// directory, which for a benchmark case is a fixture holding only the
	// patched file. Both scopes claim to be repository@commit, so a tool's
	// negative result in the narrow one was indistinguishable from a fact
	// about the wide one — on CVE-2026-44362 reverse_trace reported
	// "(no callers found)" for a function whose caller the fact layer had
	// already located in core/kernel/ree_fs_ta.c, and the Challenger read
	// that as the delegation path being dead code.
	//
	// The fixture stays the run's identity and the understanding layer's
	// input; only the tools widen. That is safe precisely because the two
	// trees agree on the file under audit: the fixture's copy is
	// byte-identical to the revision's (the benchmark oracle pins its
	// sha256), so architecture evidence and invariants written against the
	// fixture keep their line numbers here.
	promptProfile := planner.PromptProfile{
		RepoURL: manifest.RepoURL,
		Commit:  manifest.Commit,
		Focus:   cfg.Focus,
		Hint:    cfg.Hint,
	}

	var bundles []*artifacts.EvidenceBundle
	var allPacks []artifacts.CasePack
	var avoid []string

	// P4+ automatic deterministic lane: fire the structured fact layer HERE,
	// before the planner loop, so it is truly once-per-scan and independent of
	// the planner's outcome. It depends only on the CodeQL engine — built
	// during indexing, before this function runs — not on any planner
	// candidate, which is the point: this is the only planner-independent,
	// leakage-free detection route (see deterministic_facts.go). Seeding
	// allPacks before the loop is what makes the pass-1 hard-error and
	// nil-bundle paths below fall back to these grounded cases instead of
	// aborting the run — the "independent of the planner" contract made good.
	detPacks, derr := deterministicCasesFn(context.Background(), eng, db, queryPackDir, runDir, srcRoot, manifest.RepoURL, manifest.Commit, cfg.Focus)
	if derr != nil {
		return fmt.Errorf("deterministic fact lane: %w", derr)
	}
	if len(detPacks) > 0 {
		fmt.Printf("[deterministic] promoted %d grounded case pack(s) from the fact layer\n", len(detPacks))
	}
	allPacks = append(allPacks, detPacks...)

	for pass := 1; pass <= samples; pass++ {
		if samples > 1 {
			fmt.Printf("\n=== Planner pass %d/%d (avoiding %d previously-covered targets) ===\n", pass, samples, len(avoid))
		}
		result := planner.Run(context.Background(), planner.RunConfig{
			RunID:    manifest.RunID,
			RepoRoot: srcRoot,
			RunDir:   runDir,
			// Every pass restarts at round 1, so without this each one's
			// observation refs would collide with the last's — and a lead
			// raised in pass 2 would cite pass 1's evidence, from a pass
			// deliberately pointed at different code.
			SampleIndex:   pass - 1,
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
			if llm.IsPolicyRefusal(result.Err) {
				return fmt.Errorf("planner pass %d stopped by upstream policy refusal; preserved evidence at %s: %w", pass, runDir, result.Err)
			}
			if pass == 1 {
				if len(allPacks) == 0 {
					return fmt.Errorf("planner pass 1: %w (the deterministic fact lane also found no supported facts; check rounds.jsonl at %s)", result.Err, runfs.RoundsLogPath(runDir))
				}
				// Pass 1 failed but the deterministic lane already seeded
				// grounded, CodeQL-confirmed cases into allPacks — the run has
				// real output, so proceed on those rather than aborting. This is
				// the "independent of the planner" contract made concrete: a
				// planner outage no longer hides the deterministic lane's
				// findings.
				fmt.Fprintf(os.Stderr, "Warning: planner pass 1 failed (%v); proceeding with %d deterministic case pack(s)\n", result.Err, len(allPacks))
				break
			}
			// A later pass failing is not fatal — we already have
			// earlier-pass bundles to work with.
			fmt.Fprintf(os.Stderr, "Warning: planner pass %d failed, continuing with earlier passes: %v\n", pass, result.Err)
			break
		}
		if result.Bundle == nil {
			if pass == 1 {
				if len(allPacks) == 0 {
					return fmt.Errorf("planner pass 1 returned nil bundle and the deterministic fact lane found no supported facts; check rounds.jsonl at %s", runfs.RoundsLogPath(runDir))
				}
				break
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
		if len(allPacks) == 0 {
			// Defensive invariant: with samples normalized to ≥1 above, the
			// planner loop always runs pass 1, and pass 1's error/nil-bundle
			// guards already return this same error when allPacks is empty. So
			// reaching here with an empty allPacks should be impossible today —
			// the guard is retained as a fail-loud net against a future change
			// to those guards or the normalization, rather than silently
			// succeeding with zero findings.
			return fmt.Errorf("planner produced no bundles and the deterministic fact lane found no supported facts; check rounds.jsonl at %s", runfs.RoundsLogPath(runDir))
		}
		// The planner produced no bundle (every pass failed, or pass 1 returned
		// nil and we proceeded on the deterministic packs seeded above the
		// loop). Write a minimal evidence_bundle.json so the stats collector
		// (internal/stats/collector.go collectPlanner) still sees the planner
		// stage as present and records that downstream ran on deterministic
		// cases only; without it, evidence_bundle.json is absent and stats
		// misreport the planner as missing.
		if err := runfs.WriteJSON(runfs.EvidenceBundlePath(runDir), artifacts.EvidenceBundle{
			SchemaVersion: "teecheck.evidence_bundle.v1",
			RunID:         manifest.RunID,
			Repo: artifacts.RepoRef{
				URL:    manifest.RepoURL,
				Commit: manifest.Commit,
				Focus:  cfg.Focus,
			},
			PlannerMeta: artifacts.PlannerMeta{
				TerminationReason: "deterministic_only_planner_no_bundle",
			},
			FinalSummary: "planner produced no bundle; downstream ran on deterministic fact-layer cases only",
		}); err != nil {
			return fmt.Errorf("write deterministic-only evidence bundle: %w", err)
		}
	} else {
		// Merge into a single bundle for downstream: the first bundle's
		// metadata (commit, repo, run_id) stays authoritative, candidates
		// are the deduped union.
		merged := MergeEvidenceBundles(bundles)

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
	}

	// Case Packs are written exactly once, here, from the union of every
	// pass plus any deterministic pack. planner.Run deliberately writes
	// nothing to 03_cases/ — it is called once per --samples pass, so a
	// per-pass write would restart the case-%03d numbering each time and
	// leave an earlier pass's higher-numbered files orphaned among the
	// current pass's.
	//
	// Dedupe first, cap second: capping a list that still holds duplicates
	// would let the same finding consume two of the --max-cases slots. The
	// legacy HotspotIndex + RepoMap shim that used to run at this point is
	// gone — downstream consumes these packs directly instead of
	// re-deriving them from a synthesized 02_hotspots/01_repo_map pair.
	// After dedup, not before: a fact attached to a pack that dedup then
	// drops reaches nobody, which is how the 2026-07-31 run collected the
	// right ToolFact and delivered it to no agent.

	final := planner.DedupePacks(allPacks)
	if cfg.MaxCases > 0 && len(final) > cfg.MaxCases {
		fmt.Printf("[planner] capping %d case packs at --max-cases=%d (tool-grounded packs preserved)\n", len(final), cfg.MaxCases)
		// capPreservingGrounded never truncates a ToolFactRef-bearing pack to
		// make room for a planner lead — a CodeQL-confirmed case outranks a
		// hypothesis.
		final = capPreservingGrounded(final, cfg.MaxCases)
	}
	if err := planner.Write(runDir, final); err != nil {
		return fmt.Errorf("write case packs: %w", err)
	}
	fmt.Printf("Wrote %d case pack(s) to %s\n", len(final), runfs.CasePacksDir(runDir))
	return nil
}

// newFactEngine builds the CodeQL engine the fact-layer action uses, with
// both of its subprocesses (database create, database analyze) routed
// through the run's recording executor.
//
// It is a named function rather than two inline lines so the wiring has
// something a test can hold: neither codeql nor semgrep is installed in
// this project's CI image, so an end-to-end assertion on a real CodeQL
// event is not available, and the wiring would otherwise be checked by
// nothing but the compiler.
//
// The Engine outlives any single planner round, so the binding carries the
// run and the planner's agent id; per-round identity travels separately on
// the git calls the fact layer makes, which are bound from the
// ActionRequest that asked for them.
// indexAgent is the agent the program index's own subprocesses are recorded
// under: the git clone and checkout, and the CodeQL database build. It is
// not the planner — acquiring and extracting the repository is not the
// planner's work, and attributing it there made a 91-second extraction look
// like a planner round.
const indexAgent = "repo-index"

func newFactEngine(exec executor.Executor, runID string) *codeql.Engine {
	eng := codeql.New()
	eng.Exec = executor.Bind(exec, executor.Binding{
		RunID: runID,
		Agent: planner.DefaultPlannerAgentID,
	})
	return eng
}

// accumulatedLen returns how many unique candidates the dedupe
// result would have had at a given list of prior bundles. Used to
// detect "this pass added nothing new so stop".
func accumulatedLen(bundles []*artifacts.EvidenceBundle) int {
	return len(DedupeCandidates(bundles))
}

// findBuiltCodeQLDB returns the CodeQL database this run's fact layer built,
// or "" if none. trustirfacts writes it under 02_tool_facts/trustir/db/<hash>
// and marks completion with .trustirfacts-db-built.
func findBuiltCodeQLDB(runDir string) string {
	matches, err := filepath.Glob(filepath.Join(runDir, "02_tool_facts", "trustir", "db", "*", ".trustirfacts-db-built"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return filepath.Dir(matches[0])
}
