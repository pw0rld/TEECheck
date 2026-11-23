package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

// DefaultPlannerAgentID is used in events when RunConfig.AgentID is
// empty. Matches the suffix convention used by other agents
// (expert-001, challenger-001, ...).
const DefaultPlannerAgentID = "planner-001"

var errReplyBudget = errors.New("token budget cannot fit request input and minimum useful output")

const policyRefusalCoverageGap = "Investigation stopped after upstream policy refusal; open audit leads remain unreviewed."

// DefaultActionsPerRound is how many actions one round may request.
//
// The gate is measured in actions while the budget is measured in rounds.
// Its current eleven-action minimum fits inside the reconnaissance allowance;
// tests keep these constraints consistent when either side changes.
const DefaultActionsPerRound = 3

// RunConfig is the input to Run. Everything the main loop needs is
// passed explicitly — no package-level state.
type RunConfig struct {
	RunID    string
	RepoRoot string
	RunDir   string
	// Resume restores the last committed round from this run directory.
	Resume bool
	// ResumePrepared means the caller restored journals before opening Events.
	ResumePrepared bool
	Profile        PromptProfile
	Client         llm.Client
	Registry       *actions.Registry
	Budget         Budget
	Temperature    float64
	// MaxActionsPerRound caps how many actions the LLM may request in
	// one round. Defaults to DefaultActionsPerRound if zero.
	MaxActionsPerRound int
	// KnowledgeRoot is the on-disk root of the TEECheck knowledge wiki
	// (typically cfg.KnowledgeRoot from the top-level config). When
	// non-empty, Run will load `wiki/obligations/*.md` and
	// `wiki/patterns/*.md` into the system prompt so the LLM sees the
	// curated review criteria alongside the sink catalog. Empty means
	// "no obligations block" — planner still runs, just without wiki
	// context.
	KnowledgeRoot string

	// AvoidPaths lists "file::symbol" strings that previous planner
	// passes in this audit session already covered. When non-empty,
	// the round prompt will tell the LLM to avoid re-picking these
	// exact targets and to find different code paths instead. Used
	// by the multi-sample audit mode (--samples N) in pipeline.Run.
	AvoidPaths []string

	// Events records typed events for stats / replay / review UI.
	// If nil, defaults to events.Nop and the planner stays silent.
	// See internal/events for the contract.
	Events events.Recorder
	// Blobs is the content-addressed store for prompt / response /
	// tool-args bodies. When non-nil, those bodies are written there
	// and only the sha256 ref appears in events.jsonl. When nil,
	// blob fields in events stay empty — events still emit, just
	// without large bodies.
	Blobs *events.BlobStore
	// AgentID is the identifier used in events. Defaults to
	// DefaultPlannerAgentID.
	AgentID string

	// SampleIndex is which --samples pass this is. Every pass restarts at
	// round 1, so (round, action index) repeats across passes and only this
	// keeps their observation refs apart. Callers driving a single pass
	// leave it at 0.
	SampleIndex int
	// Model is the model name reported in llm_call_* events. Empty
	// is allowed; consumers may fall back to "unknown".
	Model string
	// Resolved role output limit; zero preserves the global per-call default.
	MaxOutputTokens int
	ReasoningEffort string
	// StrictContractExit refuses premature done while leads remain open/expanded,
	// freezes exploration in the convergence window, and drops uncontracted thin CasePacks.
	StrictContractExit bool
	// PreScannedTaint is validated neutral L2 evidence, not source-read credit.
	PreScannedTaint *PreScannedTaint

	// Executor is the chokepoint for subprocess-class actions
	// (currently ripgrep; future: semgrep, codeql, ...). It is
	// stamped into every ActionRequest so executor-backed handlers
	// can route through it. May be nil — handlers that need an
	// executor fail explicitly when the field is missing rather
	// than silently bypass policy and observability.
	Executor executor.Executor

	// TWEContext, Architecture, and Invariants are §7.5's prior-knowledge
	// injection into the system prompt (see PriorKnowledge's doc comment).
	// Each is independently optional; a caller that has not wired one up
	// yet (e.g. internal/pipeline's legacy Rust-focused L3 run) gets that
	// section omitted from the prompt rather than a build error.
	TWEContext   string
	Architecture *artifacts.ArchitectureModel
	Invariants   []artifacts.ProjectInvariant

	// TWEPlaybooks maps a TWE ID to the playbook-derived context a Case
	// Pack built for that TWE should carry (§24 "Case Pack 修改": common
	// defenses / common false positives). A TWE ID with no entry here
	// still gets a Case Pack — just with those two fields empty.
	TWEPlaybooks map[string]TWEPlaybookSummary
}

// TWEPlaybookSummary is the subset of a twecontext.Playbook a Case Pack
// needs (§24). It is a plain-data mirror rather than an import of
// internal/twecontext, so this package does not need to depend on playbook
// YAML loading — the caller converts twecontext.Catalog.All() into this map
// keyed by TWE ID.
type TWEPlaybookSummary struct {
	CommonDefenses       []string
	CommonFalsePositives []string
}

// RunResult is the return value of Run. Bundle is always non-nil.
type RunResult struct {
	Bundle *artifacts.EvidenceBundle
	Err    error

	// Investigations is the §7.5/§24 output of any `investigations`
	// entries the LLM's `done` payload declared: each raw entry was built
	// (internal/investigations.Build), grounded against
	// Architecture/Invariants/the repository
	// (internal/investigations.Validate) and persisted under
	// runfs.InvestigationPath. Empty when the LLM declared none this run —
	// that is a normal outcome, not an error.
	Investigations []artifacts.TWEInvestigation

	// CasePacks is the merged list from BOTH halves of the done payload,
	// not just `investigations`: the rich packs rendered from the entries
	// above (internal/investigations.BuildCasePack) plus one thin pack per
	// surviving candidate (BuildFromCandidate), combined by Merge — which
	// drops empty-target packs and folds a thin pack into the rich pack
	// naming the same file set. Nothing here has been written to
	// 03_cases/; the caller accumulates these across --samples passes and
	// persists them once (see the comment at the Merge call site).
	CasePacks []artifacts.CasePack
}

// Run drives the L3 LLM planner loop until done, budget exhaustion,
// loop detection, or error. It writes:
//
//   - runDir/04_planner/rounds.jsonl         — one JSON line per round
//   - runDir/04_planner/evidence_bundle.json — final bundle
func Run(ctx context.Context, cfg RunConfig) RunResult {
	if cfg.Registry == nil {
		return failedResult(cfg, "registry is required", "config_error")
	}
	if cfg.Client == nil {
		return failedResult(cfg, "llm client is required", "config_error")
	}
	if cfg.MaxOutputTokens < 0 || cfg.Budget.MaxTokens < 0 || cfg.Budget.MaxReconTokens < 0 || cfg.Budget.MaxInvestigationTokens < 0 {
		return failedResult(cfg, "token limits must be zero or positive", "config_error")
	}
	if cfg.Budget.MaxRounds == 0 {
		cfg.Budget = NewDefaultBudget()
	}
	if cfg.MaxActionsPerRound <= 0 {
		cfg.MaxActionsPerRound = DefaultActionsPerRound
	}
	if cfg.Events == nil {
		cfg.Events = events.Nop{}
	}
	if cfg.AgentID == "" {
		cfg.AgentID = DefaultPlannerAgentID
	}

	minimumOutput := minimumRequestOutput(cfg)
	prescan, prescanFact, prescanErr := validatePreScannedTaint(cfg)
	if prescanErr != nil {
		if cfg.Resume {
			return failedResult(cfg, prescanErr.Error(), "resume_error")
		}
		gaps := []string{"Entry taint prescan evidence was not injected: " + prescanErr.Error()}
		if cfg.PreScannedTaint != nil {
			gaps = unionStrings(gaps, cfg.PreScannedTaint.CoverageGaps)
		}
		prescan = &PreScannedTaint{CoverageGaps: gaps}
	}
	cfg.PreScannedTaint = prescan

	var resumed *Checkpoint
	if cfg.Resume {
		var err error
		resumed, err = InspectCheckpoint(cfg.RunDir, cfg.RepoRoot)
		if err != nil {
			return failedResult(cfg, err.Error(), "resume_error")
		}
		if resumed.RunID != cfg.RunID || resumed.SampleIndex != cfg.SampleIndex || resumed.Profile != cfg.Profile {
			return failedResult(cfg, "checkpoint belongs to another run, sample, or source profile", "resume_error")
		}
		if resumed.ConfigSHA256 != checkpointConfigHash(cfg) {
			return failedResult(cfg, "planner configuration changed since checkpoint", "resume_error")
		}
		if !cfg.ResumePrepared {
			if err := RestoreCheckpointJournals(resumed); err != nil {
				return failedResult(cfg, err.Error(), "resume_error")
			}
		}
		if resumed.Completed && resumed.CachedResult != nil {
			return resumed.CachedResult.RunResult()
		}
	}

	cfg.Budget.Start()
	loopStartedAt := time.Now()

	state := NewState(cfg.RunID)
	loopDet := NewLoopDetector()
	// StallDetector is intentionally NOT wired in the MVP: the current
	// design only populates Candidates in the final done action, so
	// candidate count is always 0 during exploration and the stall
	// detector would kill every run on round 3. M3b proper should
	// either let actions emit partial candidates or track a different
	// stall signal (e.g. consecutive rounds with no new distinct
	// observations).

	// observedPaths tracks every repo-relative path the LLM has
	// actually inspected. It's populated from the `path` arg of
	// read_file/tree_sitter_outline/list_dir and from the first-column
	// values of ripgrep output. The force-done prompt injects this
	// list so the LLM can only reference real files when synthesizing
	// candidates, preventing the "sgx/svc/" hallucination we saw in v10.
	observedPaths := map[string]bool{}

	obligations := LoadObligations(cfg.KnowledgeRoot)
	knowledge := PriorKnowledge{TWEText: cfg.TWEContext}
	roundsLog := runfs.RoundsLogPath(cfg.RunDir)

	// Pass A is project-first by construction, not by instruction. The
	// registry it is given does not contain twe_playbook_detail, so a call
	// to it returns "unknown action" in the same round. A prompt asking the
	// model not to use an action is a request: on run-b the planner's first
	// two actions were twe_playbook_detail calls, because the catalog sat at
	// the top of its prompt.
	reconRegistry := cfg.Registry.Without(passBOnlyActions...)

	// The reconnaissance gate, and what the project map says there is to
	// browse. A caller that budgeted no reconnaissance rounds never enters
	// the phase — reconnaissance costs rounds, and this is what those rounds
	// buy.
	projectMap, mapped := loadProjectMap(cfg.RunDir)
	recon := NewReconState(ReconModeFor(projectMap)).WithTotals(
		len(projectMap.Modules), totalFunctions(projectMap), projectMap.Repository.FileCount).
		WithEntrySurfaces(projectMap.Capabilities.EntrySurfaces, projectMap.EntrySurfaces)
	if cfg.Budget.MaxReconRounds <= 0 || !mapped {
		recon.SkipReconnaissance()
	}
	var leads []artifacts.AuditLead

	var donePayload actions.DonePayload
	var doneAccepted bool
	var doneContractsBound bool
	// Closing contracts are linked to the converted candidate index, so a
	// successful formalization replaces that candidate's thin pack instead of
	// leaving a second, unformalized copy beside it.
	var closingContracts map[int][]artifacts.CaseInvariantV2
	var terminationReason string
	var runErr error
	var coverageGaps []string
	var runErrors []artifacts.RoundError

	// executedToolFactRefs collects the ToolFact path every successful
	// fact_layer_query returned. prompt.go's `done` schema also asks the
	// model to echo tool_fact_refs back per investigation, and on
	// 2026-07-30 the CVE-2026-44362 fixed-side run did call the query, was
	// shown the path, and then reported `"tool_fact_refs": []` — so the one
	// immutable-tier artifact it produced reached none of the downstream
	// agents, all of which read CasePack.ToolFactRefs. The reference is
	// deterministic output of an action this loop executed; it does not
	// depend on the model remembering to copy a string.
	var executedToolFactRefs []string

	// observations is what this sample actually saw, by ref. It is the only
	// thing that can tell a cited fact from an invented one, and it is per
	// sample rather than per run because two --samples passes are pointed at
	// different code on purpose.
	var observations ObservationSet

	// The source tree is fingerprinted before the first request. Run artifacts
	// inside the checkout are excluded; every other file remains part of identity.
	var stable *Checkpoint
	checkpointEnabled := cfg.RunDir != "" && cfg.RepoRoot != ""
	var treeHash, binaryHash string
	if resumed != nil {
		state = resumed.State
		recon = resumed.Recon.restore()
		cfg.Budget = resumed.Budget
		elapsed := time.Duration(resumed.ElapsedNanos)
		cfg.Budget.startedAt = time.Now().Add(-elapsed)
		loopStartedAt = cfg.Budget.startedAt
		loopDet = &LoopDetector{lastAction: resumed.Loop.Action, lastArgs: resumed.Loop.Args, count: resumed.Loop.Count}
		observedPaths = resumed.ObservedPaths
		observations.ok = resumed.Observations
		leads = resumed.Leads
		executedToolFactRefs = resumed.ExecutedToolFactRefs
		coverageGaps = resumed.CoverageGaps
		runErrors = resumed.RunErrors
		donePayload, doneAccepted, closingContracts = resumed.DonePayload, resumed.DoneAccepted, resumed.ClosingContracts
		treeHash, binaryHash = resumed.TreeContentHash, resumed.ExecutableSHA256
		if resumed.InFlight != nil {
			cfg.Budget.ConsumePhaseTokens(resumed.InFlight.ReservedTokens, resumed.InFlight.Recon)
			coverageGaps = append(coverageGaps, "Interrupted LLM request charged its reserved token allowance because final usage is unknown.")
		}
		if resumed.InterruptedRound {
			coverageGaps = append(coverageGaps, "Interrupted round outputs were discarded at the last committed journal boundary; spent rounds, tokens, and query quota were retained.")
		}
		stable = resumed
	} else if checkpointEnabled {
		var err error
		treeHash, err = sourcehash.TreeExcluding(cfg.RepoRoot, []string{cfg.RunDir})
		if err != nil {
			return failedResult(cfg, "fingerprint source: "+err.Error(), "checkpoint_error")
		}
		binaryHash, err = executableHash()
		if err != nil {
			return failedResult(cfg, err.Error(), "checkpoint_error")
		}
	}
	// L2 evidence is explicitly presented, never credited as read_file source.
	state.PreScannedTaint = cfg.PreScannedTaint
	if cfg.PreScannedTaint != nil {
		coverageGaps = unionStrings(coverageGaps, cfg.PreScannedTaint.CoverageGaps)
		seedPreScannedTaint(cfg.PreScannedTaint, prescanFact, &observations, &executedToolFactRefs)
	}
	saveCommitted := func() error {
		if !checkpointEnabled {
			return nil
		}
		currentTree, err := sourcehash.TreeExcluding(cfg.RepoRoot, []string{cfg.RunDir})
		if err != nil {
			return err
		}
		if currentTree != treeHash {
			return fmt.Errorf("source contents changed during planner run")
		}
		paths := make([]string, 0, len(observedPaths))
		for p := range observedPaths {
			paths = append(paths, p)
		}
		hashes, err := sourcehash.Files(cfg.RepoRoot, paths)
		if err != nil {
			return err
		}
		cp := &Checkpoint{SchemaVersion: checkpointVersion, RunID: cfg.RunID, SampleIndex: cfg.SampleIndex, Profile: cfg.Profile,
			ConfigSHA256: checkpointConfigHash(cfg), ExecutableSHA256: binaryHash, TreeContentHash: treeHash, ObservedFileHashes: hashes,
			State: state, Recon: snapshotRecon(recon), Budget: cfg.Budget, ElapsedNanos: time.Since(loopStartedAt).Nanoseconds(),
			ObservedPaths: observedPaths, Observations: observations.ok, Loop: loopSnapshot{loopDet.lastAction, loopDet.lastArgs, loopDet.count},
			Leads: leads, ExecutedToolFactRefs: executedToolFactRefs, CoverageGaps: coverageGaps, RunErrors: runErrors, DonePayload: donePayload,
			DoneAccepted: doneAccepted, ClosingContracts: closingContracts, TerminationReason: terminationReason, AvoidPaths: cfg.AvoidPaths,
			Journals: map[string]JournalBoundary{}, runDir: cfg.RunDir}
		if len(state.Rounds) > 0 {
			cp.LastCommittedRound = state.Rounds[len(state.Rounds)-1].Round
		}
		for _, name := range checkpointJournalNames {
			boundary, err := journalBoundary(filepath.Join(cfg.RunDir, filepath.FromSlash(name)), -1)
			if err != nil {
				return err
			}
			cp.Journals[name] = boundary
		}
		cp.EventOffset = cp.Journals["events.jsonl"].Offset
		if err = writeCheckpoint(cp); err != nil {
			return err
		}
		// Freeze all maps/slices so an in-flight round cannot alter the saved state.
		stable, err = cloneCheckpoint(cp)
		return err
	}
	saveProgress := func(pending *pendingLLM) error {
		if !checkpointEnabled || stable == nil {
			return nil
		}
		cp, err := cloneCheckpoint(stable)
		if err != nil {
			return err
		}
		cp.Budget = cfg.Budget
		cp.ElapsedNanos = time.Since(loopStartedAt).Nanoseconds()
		cp.CoverageGaps = coverageGaps
		cp.InFlight = pending
		cp.InterruptedRound = cfg.Budget.RoundsUsed > cp.LastCommittedRound
		return writeCheckpoint(cp)
	}
	if resumed == nil {
		if err := saveCommitted(); err != nil {
			return failedResult(cfg, "write initial checkpoint: "+err.Error(), "checkpoint_error")
		}
	} else if err := saveProgress(nil); err != nil {
		return failedResult(cfg, "restore checkpoint budget: "+err.Error(), "checkpoint_error")
	}

loop:
	for !cfg.Budget.Exhausted() {
		if recon.Phase() == PhaseReconnaissance && cfg.Budget.ReconTokenExhausted() {
			recon.ExhaustReconTokenBudget()
		}
		inRecon := recon.Phase() == PhaseReconnaissance
		if inRecon {
			cfg.Budget.ConsumeReconRound()
			// Released at the START of the round it runs out in, so the
			// prompt below can say so. Neither escape may be silent.
			if cfg.Budget.ReconExhausted() && !recon.Satisfied() {
				recon.ExhaustReconBudget()
			}
		} else {
			cfg.Budget.ConsumeRound()
		}
		roundNum := cfg.Budget.RoundsUsed

		_ = cfg.Events.Emit(events.PlannerRoundStarted(cfg.RunID, cfg.AgentID, roundNum))

		// The registry and the system prompt both follow the phase, and the
		// phase flips mid-run when a lead opens. Rebuilding them per round
		// is what makes that flip real rather than narrated.
		registry := cfg.Registry
		if inRecon {
			registry = reconRegistry
		}
		systemPrompt := BuildSystemPrompt(
			advertisedActions(registry), obligations, knowledge, recon.Phase())

		roundPrompt := BuildRoundPrompt(state, cfg.Profile, cfg.Budget, cfg.AvoidPaths, recon)
		roundPrompt += reconStatusBlock(recon)

		isFinalRound := cfg.Budget.IsFinalRound()
		unresolvedLeads := unresolvedSampleLeads(state, cfg.RunID, cfg.SampleIndex)
		inConvergenceFreeze := cfg.StrictContractExit && !inRecon && !isFinalRound && cfg.Budget.InConvergenceWindow() && len(unresolvedLeads) > 0
		if inConvergenceFreeze {
			roundPrompt += "\n=== CONVERGENCE WINDOW — RESOLVE OPEN LEADS NOW ===\n"
			roundPrompt += "Broad exploration actions are frozen because budget is nearly exhausted.\n"
			roundPrompt += "Unresolved open/expanded lead(s): " + strings.Join(unresolvedLeads, ", ") + "\n"
			roundPrompt += "You may ONLY call `read_file` (to confirm an anchor), `update_lead`, `formalize_contract`, `close_lead`, or `done` (after leads are resolved).\n"
		}

		// Inject the list of paths the LLM has actually observed so
		// far in every round after the first. The wording is soft in
		// middle rounds (LLM should still be free to discover new
		// paths via ripgrep/list_dir) and hard in the final round
		// (the LLM MUST use these paths in candidates).
		//
		// This is the defense against path hallucination — the LLM
		// inventing plausible-but-fake paths like "sgx/svc/key.rs"
		// when the real path it saw was "sgx/service/src/lib.rs".
		// v10 dogfood showed 100% hallucinated paths without this;
		// v11+ with only-final-round injection showed 0 hallucinated
		// paths at done time but still occasional mid-round invented
		// paths. T1.3 closes the mid-round gap.
		if len(observedPaths) > 0 {
			paths := make([]string, 0, len(observedPaths))
			for p := range observedPaths {
				paths = append(paths, p)
			}
			sort.Strings(paths)

			if isFinalRound {
				roundPrompt += "\n=== FINAL ROUND — BUDGET EXHAUSTING ===\n"
				roundPrompt += "This is your FINAL round. You have NO more rounds after this.\n"
				roundPrompt += "You MUST respond with EXACTLY ONE action: `done`.\n"
				roundPrompt += "Synthesize candidates from the observations in previous rounds. Even partial findings are valuable.\n"
				roundPrompt += "Do NOT call list_dir, ripgrep, read_file, or any other exploration action. Only `done`.\n"
				roundPrompt += "\nOBSERVED PATHS (the ONLY paths you may cite in candidates[].paths):\n"
				for _, p := range paths {
					roundPrompt += "  - " + p + "\n"
				}
				roundPrompt += "\nDo NOT abbreviate directory names. Do NOT invent paths. Do NOT cite paths you have not actually seen.\n"
			} else {
				roundPrompt += "\nPATHS OBSERVED SO FAR (you may reference these directly; new paths MUST come from ripgrep or list_dir output, never invented):\n"
				for _, p := range paths {
					roundPrompt += "  - " + p + "\n"
				}
			}
		} else if isFinalRound {
			// No observations yet and it's the final round — still
			// force done, but there's nothing to constrain against.
			roundPrompt += "\n=== FINAL ROUND — BUDGET EXHAUSTING ===\n"
			roundPrompt += "This is your FINAL round. You MUST respond with EXACTLY ONE action: `done`.\n"
			roundPrompt += "You have not inspected any files yet. Emit a done with empty candidates[] and a summary explaining what would have been needed.\n"
		}

		// Check the complete next request before dispatch. Crossing a phase
		// allowance releases reconnaissance; crossing the exploration allowance
		// switches to a compact final prompt while its token reserve remains.
		predictedInput := estimateRequestInputTokens(systemPrompt, roundPrompt)
		if inRecon && !isFinalRound && requestOutputBudget(cfg, predictedInput, true, false) < minimumOutput {
			recon.ExhaustReconTokenBudget()
			inRecon = false
			registry = cfg.Registry
			systemPrompt = BuildSystemPrompt(advertisedActions(cfg.Registry), obligations, knowledge, recon.Phase())
			roundPrompt = BuildRoundPrompt(state, cfg.Profile, cfg.Budget, cfg.AvoidPaths, recon) + reconStatusBlock(recon)
			predictedInput = estimateRequestInputTokens(systemPrompt, roundPrompt)
		}
		if !isFinalRound && requestOutputBudget(cfg, predictedInput, inRecon, false) < minimumOutput {
			isFinalRound = true
		}
		prepareFinal := func(prompt string, compact bool) string {
			isFinalRound = true
			// Convergence is investigation work even when reconnaissance has
			// not completed. Its own allowance must not block the final reply.
			if inRecon {
				recon.ExhaustReconTokenBudget()
				inRecon = false
				registry = cfg.Registry
			}
			if !strings.Contains(prompt, "FINAL ROUND") {
				prompt += "\nFINAL ROUND — convergence reserve. Reply with exactly one done action and no exploration actions.\n"
			}
			if compact || requestOutputBudget(cfg, estimateRequestInputTokens(systemPrompt, prompt), false, true) < minimumOutput {
				available := cfg.Budget.OutputAllowance(0, false, true)
				systemPrompt, prompt = convergencePromptWithMinimum(state, observedPaths, available, minimumOutput)
			}
			return prompt
		}
		if isFinalRound {
			roundPrompt = prepareFinal(roundPrompt, false)
		}

		// TotalRounds, not MaxRounds: reconnaissance rounds are granted on
		// top of the investigation budget, so the ceiling grows as they are
		// spent. The run that printed "round 6/8" had used 6 of 14.
		fmt.Fprintf(os.Stdout, "[planner] round %d/%d — calling LLM...\n", roundNum, cfg.Budget.TotalRounds())

		// Token cost for this round. A corrective re-ask ACCUMULATES onto
		// these rather than replacing them: the round really did cost two
		// calls, and rounds.jsonl must not under-report it.
		var tokensIn, tokensOut int

		// askOnce performs one LLM call for this round, including token
		// accounting, blob persistence and the started/completed event pair.
		// It is a closure rather than a method so the corrective re-ask below
		// reuses exactly the same accounting instead of a second copy of it.
		askOnce := func(prompt string) (llm.GenerateResponse, error) {
			inputBudget := estimateRequestInputTokens(systemPrompt, prompt)
			outputBudget := requestOutputBudget(cfg, inputBudget, inRecon, isFinalRound)
			if outputBudget < minimumOutput {
				return llm.GenerateResponse{}, fmt.Errorf("%w: need %d output tokens, have %d", errReplyBudget, minimumOutput, outputBudget)
			}
			genReq := llm.GenerateRequest{
				SystemPrompt:    systemPrompt,
				Messages:        []llm.Message{{Role: "user", Content: prompt}},
				Temperature:     cfg.Temperature,
				JSONMode:        true,
				MaxOutputTokens: outputBudget,
			}
			_ = cfg.Events.Emit(events.LLMCallStarted(cfg.RunID, cfg.AgentID, cfg.Model, roundNum))
			requestCtx := ctx
			if cfg.Budget.WallClock > 0 {
				var cancel context.CancelFunc
				requestCtx, cancel = context.WithDeadline(ctx, cfg.Budget.startedAt.Add(cfg.Budget.WallClock))
				defer cancel()
			}
			if err := saveProgress(&pendingLLM{ReservedTokens: inputBudget + outputBudget, Recon: inRecon}); err != nil {
				return llm.GenerateResponse{}, fmt.Errorf("persist request checkpoint: %w", err)
			}
			stopHeartbeat := func() error { return nil }
			if checkpointEnabled {
				stopHeartbeat = checkpointHeartbeat(cfg.RunDir)
			}
			var genResp llm.GenerateResponse
			var err error
			func() {
				defer func() {
					if heartbeatErr := stopHeartbeat(); heartbeatErr != nil && err == nil {
						err = fmt.Errorf("persist active time: %w", heartbeatErr)
					}
				}()
				genResp, err = cfg.Client.Generate(requestCtx, genReq)
			}()
			if err != nil {
				var callIn, callOut int
				if genResp.Usage.PromptTokens > 0 || genResp.Usage.CompletionTokens > 0 || genResp.Usage.TotalTokens > 0 {
					callIn, callOut = accountedUsage(genResp, inputBudget)
					cfg.Budget.ConsumePhaseTokens(callIn+callOut, inRecon)
					tokensIn += callIn
					tokensOut += callOut
				}
				// Emit a completion event with Error populated so
				// downstream consumers can pair the started/completed
				// events even on failure.
				// The bytes the client got as far as, even though the
				// call failed — a non-2xx body or a timed-out request is
				// exactly what needs reading afterwards.
				failed := events.LLMCallCompleted(cfg.RunID, cfg.AgentID, cfg.Model, roundNum, callIn, callOut, "", "").
					WithWireBodies(
						events.BestEffortRef(cfg.Blobs, []byte(genResp.RawRequest)),
						events.BestEffortRef(cfg.Blobs, []byte(genResp.Raw)))
				failed.Error = err.Error()
				_ = cfg.Events.Emit(failed)
				var unresolvedRequest *pendingLLM
				if callIn+callOut == 0 && !llm.IsPolicyRefusal(err) {
					unresolvedRequest = &pendingLLM{ReservedTokens: inputBudget + outputBudget, Recon: inRecon}
				}
				if checkpointErr := saveProgress(unresolvedRequest); checkpointErr != nil {
					return llm.GenerateResponse{}, fmt.Errorf("%w; persist request budget: %v", err, checkpointErr)
				}
				return llm.GenerateResponse{}, err
			}
			// Credit entry reading only after these actual source excerpts
			// reached a model request. A read followed by done in the same
			// action batch has not yet shown its response to the model.
			observePresentedEntrySources(recon, state, prompt)

			// Missing input/output fields are independently unknown, never
			// free. Preserve a larger provider total (e.g. reasoning tokens).
			callIn, callOut := accountedUsage(genResp, inputBudget)

			cfg.Budget.ConsumePhaseTokens(callIn+callOut, inRecon)
			tokensIn += callIn
			tokensOut += callOut

			// Persist prompt + response bodies to the blob store (if
			// configured) and emit llm_call_completed with refs only.
			var promptBlob, responseBlob string
			if cfg.Blobs != nil {
				if ref, err := cfg.Blobs.WriteString(systemPrompt + "\n\n---\n\n" + prompt); err == nil {
					promptBlob = ref
				}
				if ref, err := cfg.Blobs.WriteString(genResp.Text); err == nil {
					responseBlob = ref
				}
			}
			// The wire bodies are kept alongside the readable pair, not
			// instead of it: promptBlob is a prompt joined for a human and
			// responseBlob is the message the parser extracted, while these
			// two are what actually crossed the wire.
			_ = cfg.Events.Emit(events.LLMCallCompleted(
				cfg.RunID, cfg.AgentID, cfg.Model, roundNum, callIn, callOut, promptBlob, responseBlob).
				WithWireBodies(
					events.BestEffortRef(cfg.Blobs, []byte(genResp.RawRequest)),
					events.BestEffortRef(cfg.Blobs, []byte(genResp.Raw))))
			if err := saveProgress(nil); err != nil {
				return llm.GenerateResponse{}, fmt.Errorf("persist request budget: %w", err)
			}
			return genResp, nil
		}

		stopAfterPolicyRefusal := func(err error) {
			runErr = fmt.Errorf("round %d: llm generate: %w", roundNum, err)
			// A policy decision is a terminal upstream result, not a
			// request to alter the prompt or route it through another role.
			terminationReason = "policy_refusal"
			coverageGaps = append(coverageGaps, policyRefusalCoverageGap)
			runErrors = append(runErrors, artifacts.RoundError{Round: roundNum, Action: "llm", Error: err.Error()})
			failedRound := artifacts.RoundRecord{
				Round: roundNum, TokensIn: tokensIn, TokensOut: tokensOut,
				CoverageGaps: []string{policyRefusalCoverageGap},
			}
			if persistErr := state.AppendRoundAndPersist(failedRound, roundsLog); persistErr != nil {
				runErr = fmt.Errorf("%w; persist refusal checkpoint: %v", runErr, persistErr)
				return
			}
			_ = cfg.Events.Emit(events.PlannerRoundCompleted(cfg.RunID, cfg.AgentID, roundNum, 0, 0))
			if err := saveCommitted(); err != nil {
				runErr = fmt.Errorf("persist checkpoint: %w", err)
				terminationReason = "checkpoint_error"
			}
		}

		stopForBudget := func(reason string, cause error) {
			terminationReason = reason
			gap := "Planner stopped at its budget limit (" + reason + "): " + cause.Error()
			coverageGaps = append(coverageGaps, gap)
			round := artifacts.RoundRecord{Round: roundNum, TokensIn: tokensIn, TokensOut: tokensOut, CoverageGaps: []string{gap}}
			if err := state.AppendRoundAndPersist(round, roundsLog); err != nil {
				runErr, terminationReason = err, "persist_error"
				return
			}
			_ = cfg.Events.Emit(events.PlannerRoundCompleted(cfg.RunID, cfg.AgentID, roundNum, 0, 0))
			if err := saveCommitted(); err != nil {
				runErr, terminationReason = err, "checkpoint_error"
			}
		}

		genResp, err := askOnce(roundPrompt)
		if err != nil {
			if errors.Is(err, errReplyBudget) {
				stopForBudget("token_budget_insufficient", err)
			} else if errors.Is(err, context.DeadlineExceeded) && !llm.IsPolicyRefusal(err) && cfg.Budget.WallClock > 0 && time.Since(cfg.Budget.startedAt) >= cfg.Budget.WallClock {
				stopForBudget("wall_clock", err)
			} else if llm.IsPolicyRefusal(err) {
				stopAfterPolicyRefusal(err)
			} else {
				runErr = fmt.Errorf("round %d: llm generate: %w", roundNum, err)
				terminationReason = "llm_error"
			}
			break
		}

		parsed, parseErr := ParseLLMResponse(genResp.Text)
		if parseErr != nil {
			// One corrective re-ask before giving up. response_format is not
			// honoured on every round by every endpoint, and models that
			// narrate before acting ("Let me continue reading.") produce a
			// reply with no JSON object in it. Discarding seven good rounds
			// because the eighth slipped is the wrong trade — the cost of
			// re-asking is one extra call, the cost of not re-asking is the
			// whole run.
			// The message carries parseErr rather than a fixed sentence.
			// It used to read "reply was not a JSON object" whatever went
			// wrong, and on 2026-08-04 that was false: the reply WAS a JSON
			// object, just wrapped in one the schema does not describe, and
			// the real error was "no actions". Diagnosing it from the log
			// alone sent the investigation the wrong way for an afternoon.
			fmt.Fprintf(os.Stdout, "[planner] round %d: %v — re-asking once\n", roundNum, parseErr)
			retryPrompt := roundPrompt + "\n\n=== YOUR PREVIOUS REPLY WAS REJECTED ===\n" +
				"It was rejected because: " + parseErr.Error() + "\n" +
				"Do not narrate, explain, or announce what you are about to do. Do not wrap the object in another object.\n" +
				"Reply with the JSON object described in the response format and NOTHING else — no prose before it, no prose after it, no markdown fence.\n" +
				"Your rejected reply began: " + truncate(genResp.Text, 200) + "\n"
			if requestOutputBudget(cfg, estimateRequestInputTokens(systemPrompt, retryPrompt), inRecon, isFinalRound) < minimumOutput {
				retryPrompt = prepareFinal(retryPrompt, true)
			}
			if retryResp, retryErr := askOnce(retryPrompt); errors.Is(retryErr, errReplyBudget) {
				stopForBudget("token_budget_insufficient", retryErr)
				break loop
			} else if errors.Is(retryErr, context.DeadlineExceeded) && !llm.IsPolicyRefusal(retryErr) && cfg.Budget.WallClock > 0 && time.Since(cfg.Budget.startedAt) >= cfg.Budget.WallClock {
				stopForBudget("wall_clock", retryErr)
				break loop
			} else if llm.IsPolicyRefusal(retryErr) {
				stopAfterPolicyRefusal(retryErr)
				break loop
			} else if retryErr == nil {
				genResp = retryResp
				parsed, parseErr = ParseLLMResponse(genResp.Text)
			}
		}
		if parseErr != nil {
			runErr = fmt.Errorf("round %d: %w", roundNum, parseErr)
			terminationReason = "llm_malformed"
			if err := state.AppendRoundAndPersist(artifacts.RoundRecord{
				Round:   roundNum,
				Thought: "<unparseable>: " + truncate(genResp.Text, 500),
			}, roundsLog); err != nil {
				runErr = fmt.Errorf("persist malformed round: %w", err)
				terminationReason = "persist_error"
				break
			}
			_ = cfg.Events.Emit(events.PlannerRoundCompleted(cfg.RunID, cfg.AgentID, roundNum, 0, 0))
			if err := saveCommitted(); err != nil {
				runErr = fmt.Errorf("persist checkpoint: %w", err)
				terminationReason = "checkpoint_error"
			}
			break
		}

		roundRec := artifacts.RoundRecord{
			Round:     roundNum,
			Thought:   parsed.Thought,
			TokensIn:  tokensIn,
			TokensOut: tokensOut,
		}
		emitRoundDone := func() {
			_ = cfg.Events.Emit(events.PlannerRoundCompleted(
				cfg.RunID, cfg.AgentID, roundNum,
				len(roundRec.Actions), len(roundRec.Observations)))
		}

		actionLimit := len(parsed.Actions)
		if actionLimit > cfg.MaxActionsPerRound {
			actionLimit = cfg.MaxActionsPerRound
		}
		for i := 0; i < actionLimit; i++ {
			act := parsed.Actions[i]
			argsStr := string(act.Args)

			roundRec.Actions = append(roundRec.Actions, artifacts.RoundAction{
				Name: act.Name,
				Args: act.Args,
			})

			if loopDet.ShouldReject(act.Name, argsStr) {
				// No Ref: a ref names an observation, and a rejected
				// action made none. ActionIndex still lands, so the
				// observation list stays alignable with the action list
				// that produced it.
				roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
					Name:        act.Name,
					OK:          false,
					ActionIndex: i,
					Error:       "loop detector: repeating same (action, args) — try a different action or args",
				})
				continue
			}

			fmt.Fprintf(os.Stdout, "[planner]   -> %s\n", act.Name)

			// Executor-backed handlers (ripgrep today; semgrep,
			// codeql, ... in future commits) emit their own
			// tool_call_started / tool_call_completed events through
			// the executor. The planner must skip its manual emit
			// path for those actions or events.jsonl will record
			// duplicates and stats action_mix doubles.
			executorBacked := registry.IsExecutorBacked(act.Name)

			if !executorBacked {
				toolArgsBlob := events.BestEffortRef(cfg.Blobs, act.Args)
				_ = cfg.Events.Emit(events.ToolCallStarted(cfg.RunID, cfg.AgentID, act.Name, roundNum, toolArgsBlob))
			}

			// open_audit_lead and the reconnaissance gate on `done` are
			// dispatched here rather than through the registry. Both need
			// the live ReconState and this pass's observation set, and an
			// actions.Handler receives only an ActionRequest — a handler
			// would have to re-read artifacts from disk and guess what the
			// planner saw, which is the kind of reconstruction that
			// produces a citation to something nobody looked at.
			// Captured before dispatch: open_audit_lead is the action that
			// flips the phase, and it was itself made in the phase before
			// the flip.
			phaseAtAction := recon.Phase()

			currentUnresolved := unresolvedSampleLeads(state, cfg.RunID, cfg.SampleIndex)
			var result actions.ActionResult
			switch {
			case isFinalRound && act.Name != "done":
				result = actions.ActionResult{Name: act.Name, Error: "final round permits only done; exploration would spend the convergence reserve"}
			case inConvergenceFreeze && !allowedInConvergenceFreeze(act.Name):
				result = actions.ActionResult{
					Name:  act.Name,
					OK:    false,
					Error: "convergence freeze: broad exploration is disabled; call formalize_contract or close_lead for unresolved lead(s): " + strings.Join(currentUnresolved, ", "),
				}
			case act.Name == ActionOpenAuditLead:
				var lead artifacts.AuditLead
				lead, result = openLead(cfg, recon, observations, act.Args, roundNum, state)
				if result.OK {
					leads = append(leads, lead)
					state.AuditLeads = append(state.AuditLeads, lead)
				}
			case act.Name == ActionUpdateLead:
				result = updateLead(cfg, state, observations, executedToolFactRefs, act.Args, roundNum)
				if result.OK {
					leads = cloneLeadsSlice(state.AuditLeads)
				}
			case act.Name == ActionFormalizeContract:
				result = formalizeContract(cfg, state, observations, executedToolFactRefs, roundRec, act.Args)
				if result.OK {
					leads = cloneLeadsSlice(state.AuditLeads)
				}
			case act.Name == ActionCloseLead:
				result = closeLead(cfg, state, observations, executedToolFactRefs, act.Args, roundNum)
				if result.OK {
					leads = cloneLeadsSlice(state.AuditLeads)
				}
			case act.Name == "done" && !recon.AllowDone(isFinalRound):
				result = actions.ActionResult{
					Name: "done",
					OK:   false,
					Error: "done refused: you have not yet seen enough of this project to " +
						"conclude anything about it. Still needed:\n" + recon.DoneUnmet(),
				}
			default:
				request := actions.ActionRequest{
					Name:       act.Name,
					Args:       act.Args,
					RepoRoot:   cfg.RepoRoot,
					RunDir:     cfg.RunDir,
					Repository: cfg.Profile.RepoURL,
					Commit:     cfg.Profile.Commit,
					Executor:   cfg.Executor,
					RunID:      cfg.RunID,
					Agent:      cfg.AgentID,
					Round:      roundNum,
				}
				stopQueryHeartbeat := func() error { return nil }
				if act.Name == actions.TraceTaintAction {
					timeout := cfg.Budget.TaintQueryTimeout
					if timeout <= 0 {
						timeout = 5 * time.Minute
					}
					if cfg.Budget.WallClock > 0 {
						remaining := time.Until(cfg.Budget.startedAt.Add(cfg.Budget.WallClock))
						if remaining <= 0 {
							result = actions.ActionResult{Name: act.Name, Error: "planner wall-clock budget exhausted"}
							break
						}
						if remaining < timeout {
							timeout = remaining
						}
					}
					request.TracePolicy = &actions.TracePolicy{ObservedSymbol: recon.SawSymbol, TakeQuery: func() bool {
						if !cfg.Budget.ConsumeTaintQuery() {
							return false
						}
						if err := saveProgress(nil); err != nil {
							runErr = fmt.Errorf("persist query budget: %w", err)
							return false
						}
						if checkpointEnabled {
							stopQueryHeartbeat = checkpointHeartbeat(cfg.RunDir)
						}
						return true
					}, Timeout: timeout}
				}
				func() {
					defer func() {
						if err := stopQueryHeartbeat(); err != nil {
							runErr = fmt.Errorf("persist active query time: %w", err)
						}
					}()
					result = registry.Run(ctx, request)
				}()
			}
			// Validate, bind, and persist NEW closing drafts while keeping already
			// machine-accepted contracts in state.Contracts intact, then verify real
			// AuditLead state transitions BEFORE committing `done`.
			var finishLoopAfterObservation bool
			if result.Name == "done" && result.OK {
				var trialPayload actions.DonePayload
				if uerr := json.Unmarshal([]byte(result.Output), &trialPayload); uerr != nil {
					result = actions.ActionResult{Name: "done", OK: false, Error: "invalid done payload: " + uerr.Error()}
				} else {
					acceptedSnapshot := cloneContractsSlice(state.Contracts)
					trialPayload.CaseInvariants = filterOutAcceptedDrafts(trialPayload.CaseInvariants, acceptedSnapshot)
					closingState := *state
					closingState.Rounds = append(append([]artifacts.RoundRecord(nil), state.Rounds...), roundRec)
					trialClosing, closeErrors, closeGaps, closeErr := formalizeCandidates(ctx, cfg, &trialPayload, &closingState, observations, func(system, prompt string) (llm.GenerateResponse, error) {
						savedSystem, savedInRecon, savedFinal := systemPrompt, inRecon, isFinalRound
						systemPrompt = system
						inRecon, isFinalRound = false, true
						defer func() {
							systemPrompt, inRecon, isFinalRound = savedSystem, savedInRecon, savedFinal
						}()
						return askOnce(prompt)
					})
					roundRec.TokensIn, roundRec.TokensOut = tokensIn, tokensOut
					runErrors = append(runErrors, closeErrors...)
					coverageGaps = append(coverageGaps, closeGaps...)
					roundRec.CoverageGaps = append(roundRec.CoverageGaps, closeGaps...)

					if closeErr != nil {
						convertedCands, _ := convertCandidates(trialPayload.Candidates, cfg.RepoRoot)
						acceptedClosing, acceptedStandalone := partitionAcceptedContracts(acceptedSnapshot, convertedCands)
						trialPayload.CaseInvariants = acceptedStandalone
						donePayload = trialPayload
						doneAccepted = true
						doneContractsBound = true
						closingContracts = acceptedClosing
						if errors.Is(closeErr, errReplyBudget) {
							terminationReason = "token_budget_insufficient"
						} else {
							runErr = fmt.Errorf("round %d: contract formalization: %w", roundNum, closeErr)
							terminationReason = "llm_error"
							if cfg.Budget.WallClock > 0 && time.Since(cfg.Budget.startedAt) >= cfg.Budget.WallClock {
								terminationReason = "wall_clock"
							}
							if llm.IsPolicyRefusal(closeErr) {
								terminationReason = "policy_refusal"
								coverageGaps = append(coverageGaps, policyRefusalCoverageGap)
								roundRec.CoverageGaps = append(roundRec.CoverageGaps, policyRefusalCoverageGap)
							}
						}
						finishLoopAfterObservation = true
					} else {
						convertedCands, _ := convertCandidates(trialPayload.Candidates, cfg.RepoRoot)
						acceptedClosing, acceptedStandalone := partitionAcceptedContracts(acceptedSnapshot, convertedCands)
						var bindErrors []artifacts.RoundError
						boundClosing := make(map[int][]artifacts.CaseInvariantV2, len(trialClosing)+len(acceptedClosing))
						for idx, accList := range acceptedClosing {
							boundClosing[idx] = cloneContractsSlice(accList)
						}
						candIndices := make([]int, 0, len(trialClosing))
						for idx := range trialClosing {
							candIndices = append(candIndices, idx)
						}
						sort.Ints(candIndices)
						for _, idx := range candIndices {
							boundList, errs := bindPlannerContractsWithState(trialClosing[idx], cfg, state, &observations, executedToolFactRefs, &roundRec)
							boundClosing[idx] = contracts.MergeAll(boundClosing[idx], boundList)
							bindErrors = append(bindErrors, errs...)
						}
						boundStandalone, standaloneErrs := bindPlannerContractsWithState(trialPayload.CaseInvariants, cfg, state, &observations, executedToolFactRefs, &roundRec)
						trialPayload.CaseInvariants = contracts.MergeAll(acceptedStandalone, boundStandalone)
						bindErrors = append(bindErrors, standaloneErrs...)
						invBindErrs := bindInvestigationContracts(trialPayload.Investigations, cfg, state, &observations, executedToolFactRefs, &roundRec)
						bindErrors = append(bindErrors, invBindErrs...)
						runErrors = append(runErrors, bindErrors...)
						leads = cloneLeadsSlice(state.AuditLeads)

						stillUnresolved := unresolvedSampleLeads(state, cfg.RunID, cfg.SampleIndex)
						if cfg.StrictContractExit && !isFinalRound && len(stillUnresolved) > 0 {
							var diag []string
							for _, e := range append(closeErrors, bindErrors...) {
								diag = append(diag, e.Error)
							}
							for _, g := range closeGaps {
								diag = append(diag, g)
							}
							msg := "done refused: unresolved audit lead(s) " + strings.Join(stillUnresolved, ", ") +
								" remain open after contract validation/formalization; bind each lead with a valid CaseInvariantV2 (formalize_contract) or archive it with close_lead before concluding"
							if len(diag) > 0 {
								msg += ". Diagnostics: " + strings.Join(diag, "; ")
							}
							result = actions.ActionResult{
								Name:  "done",
								OK:    false,
								Error: msg,
							}
						} else {
							donePayload = trialPayload
							doneAccepted = true
							doneContractsBound = true
							closingContracts = boundClosing
							if cfg.StrictContractExit && len(stillUnresolved) > 0 {
								terminationReason = "unresolved_leads_incomplete"
								gap := "Planner stopped at budget exhaustion with unresolved audit lead(s): " + strings.Join(stillUnresolved, ", ")
								coverageGaps = unionStrings(coverageGaps, []string{gap})
								roundRec.CoverageGaps = unionStrings(roundRec.CoverageGaps, []string{gap})
							} else {
								terminationReason = "llm_done"
							}
							finishLoopAfterObservation = true
						}
					}
				}
			}

			loopDet.Record(act.Name, argsStr)
			if act.Name != "read_file" && act.Name != "tree_sitter_outline" {
				recon.ObserveAction(act.Name, act.Args, result.OK)
			}

			outputBlob := events.BestEffortRef(cfg.Blobs, []byte(result.Output))
			if !executorBacked {
				_ = cfg.Events.Emit(events.ToolCallCompleted(cfg.RunID, cfg.AgentID, result.Name, roundNum, result.OK, result.DurationMs, outputBlob, result.Error))
			}

			body, cutHere := excerpt(result.Output, outputBlob)
			recon.ObserveSourceOutput(act.Name, act.Args, body, result.OK)

			ref := MakeObservationRef(cfg.RunID, cfg.SampleIndex, roundNum, i, outputBlob)
			observations.Record(ref, result.OK)
			_ = cfg.Events.Emit(events.PlannerObservationRecorded(
				cfg.RunID, cfg.AgentID, result.Name, roundNum, cfg.SampleIndex,
				result.OK, ref, outputBlob))

			roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
				Name:        result.Name,
				OK:          result.OK,
				Ref:         ref,
				OutputBlob:  outputBlob,
				ActionIndex: i,
				Phase:       phaseAtAction,
				Output:      body,
				Error:       result.Error,
				Truncated:   result.Truncated || cutHere,
				DurationMs:  result.DurationMs,
			})

			if result.OK {
				trackObservedPaths(act.Name, act.Args, result.Output, cfg.RepoRoot, observedPaths)
			}

			if (result.Name == "fact_layer_query" || result.Name == actions.TraceTaintAction) && result.OK {
				if ref := toolFactRefFrom(result.Output); ref != "" {
					executedToolFactRefs = append(executedToolFactRefs, ref)
				}
			}

			if result.Name == "twe_playbook_detail" && result.OK {
				var detailArgs struct {
					TWEID string `json:"twe_id"`
				}
				if err := json.Unmarshal(act.Args, &detailArgs); err == nil && detailArgs.TWEID != "" {
					state.AddPlaybookDetail(detailArgs.TWEID, result.Output)
				}
			}

			if finishLoopAfterObservation {
				if err := state.AppendRoundAndPersist(roundRec, roundsLog); err != nil {
					runErr = fmt.Errorf("round %d: persist: %w", roundNum, err)
					terminationReason = "persist_error"
					emitRoundDone()
					break loop
				}
				emitRoundDone()
				if err := saveCommitted(); err != nil {
					runErr = fmt.Errorf("persist checkpoint: %w", err)
					terminationReason = "checkpoint_error"
				}
				break loop
			}
		}

		if err := state.AppendRoundAndPersist(roundRec, roundsLog); err != nil {
			runErr = fmt.Errorf("round %d: persist: %w", roundNum, err)
			terminationReason = "persist_error"
			emitRoundDone()
			break
		}
		emitRoundDone()
		if err := saveCommitted(); err != nil {
			runErr = fmt.Errorf("persist checkpoint: %w", err)
			terminationReason = "checkpoint_error"
			break
		}
	}

	leads = cloneLeadsSlice(state.AuditLeads)
	if terminationReason == "" {
		terminationReason = cfg.Budget.TerminationReason()
	}
	// A later cancellation/refusal must not erase contracts already accepted
	// by formalize_contract in earlier rounds.
	if !doneAccepted {
		donePayload.CaseInvariants = cloneContractsSlice(state.Contracts)
		doneContractsBound = true
	}
	if terminationReason == "" {
		terminationReason = "unknown"
	}
	if cfg.StrictContractExit {
		if unresolvedEnd := unresolvedSampleLeads(state, cfg.RunID, cfg.SampleIndex); len(unresolvedEnd) > 0 {
			if runErr == nil && (terminationReason == "llm_done" || terminationReason == "unknown") {
				terminationReason = "unresolved_leads_incomplete"
			}
			gap := "Planner stopped with unresolved audit lead(s): " + strings.Join(unresolvedEnd, ", ")
			coverageGaps = unionStrings(coverageGaps, []string{gap})
		}
	}
	if runErr == nil && terminationReason != "token_budget_insufficient" && terminationReason != "unresolved_leads_incomplete" && recon.TerminationReason(true) == terminationReconIncomplete {
		terminationReason = terminationReconIncomplete
	}
	if runErr == nil && recon.DoneCoverageIncomplete() {
		if terminationReason != "token_budget_insufficient" && terminationReason != "unresolved_leads_incomplete" {
			terminationReason = terminationReconIncomplete
			if entry := recon.EntryCoverage(); entry.GateApplies && len(recon.EntryCoverageGaps()) > 0 {
				terminationReason = "entry_coverage_incomplete"
			}
		}
		gap := "Planner stopped before normal zero-lead completion requirements were met: " + recon.DoneUnmet()
		coverageGaps = append(coverageGaps, gap)
	}

	if err := writeCoverageLedger(cfg, recon, projectMap, len(leads), state); err != nil {
		fmt.Fprintf(os.Stdout, "[planner] coverage ledger not written: %v\n", err)
	}

	bundle := &artifacts.EvidenceBundle{
		SchemaVersion: "teecheck.evidence_bundle.v1",
		RunID:         cfg.RunID,
		Repo: artifacts.RepoRef{
			URL:    cfg.Profile.RepoURL,
			Commit: cfg.Profile.Commit,
			Focus:  cfg.Profile.Focus,
		},
		PlannerMeta: artifacts.PlannerMeta{
			TaintQueriesUsed:  cfg.Budget.TaintQueriesUsed,
			RoundsUsed:        cfg.Budget.RoundsUsed,
			RoundsBudget:      cfg.Budget.TotalRounds(),
			TokensUsed:        cfg.Budget.TokensUsed,
			WallClockMs:       time.Since(loopStartedAt).Milliseconds(),
			TerminationReason: terminationReason,
		},
		FinalSummary: donePayload.Summary,
		CoverageGaps: coverageGaps,
		Errors:       runErrors,
	}
	if terminationReason == "policy_refusal" {
		bundle.FinalSummary = policyRefusalCoverageGap
	}
	candidates, droppedErrors := convertCandidates(donePayload.Candidates, cfg.RepoRoot)
	bundle.Candidates = candidates
	if len(droppedErrors) > 0 {
		bundle.Errors = append(bundle.Errors, droppedErrors...)
		fmt.Fprintf(os.Stdout, "[planner] dropped %d hallucinated path(s) from candidates\n", len(droppedErrors))
	}

	bundlePath := runfs.EvidenceBundlePath(cfg.RunDir)
	if err := runfs.WriteJSON(bundlePath, bundle); err != nil {
		if runErr == nil {
			runErr = fmt.Errorf("write evidence bundle: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stdout, "[planner] evidence bundle written to %s\n", bundlePath)
	}

	invs, packs, invErrors := processInvestigations(donePayload.Investigations, cfg, state, executedToolFactRefs)
	if len(invErrors) > 0 {
		bundle.Errors = append(bundle.Errors, invErrors...)
	}

	// Both halves of the done payload become Case Packs. candidates and
	// investigations are independent lists with no id linking them
	// (prompt.go's done schema), and investigations is optional — so
	// neither can be derived from the other, and dropping either loses runs.
	//
	// bundle.Candidates is used rather than donePayload.Candidates because
	// convertCandidates (above) has already dropped hallucinated paths.
	//
	// invErrors has already been folded into bundle.Errors, so anything new
	// must be appended to bundle.Errors directly — appending to invErrors
	// here would silently discard it.
	var thin []artifacts.CasePack
	if manifest, err := runfs.LoadManifest(cfg.RunDir); err != nil {
		// Deliberately no zero-value Manifest fallback: it would mint
		// CaseIDs like "repo@:tee:candidate:001" that look normal but say
		// nothing about their origin. Record the failure and skip the thin
		// packs; the rich packs still reach the caller.
		bundle.Errors = append(bundle.Errors, artifacts.RoundError{
			Round: -1, Action: "case_pack.manifest", Error: err.Error()})
	} else {
		for i, cand := range bundle.Candidates {
			pack := BuildFromCandidate(cand, manifest, i)
			bound := closingContracts[i]
			if !doneContractsBound && runErr == nil && len(bound) > 0 {
				var errs []artifacts.RoundError
				bound, errs = bindPlannerContractsWithState(bound, cfg, state, &observations, executedToolFactRefs, nil)
				bundle.Errors = append(bundle.Errors, errs...)
			}
			for _, c := range bound {
				if c.Grounding != "source_bound" {
					continue
				}
				pack.CaseInvariants = append(pack.CaseInvariants, c)
				pack.RelatedTWEs = unionStrings(pack.RelatedTWEs, c.RelatedTWEs)
				for _, subject := range c.Subjects {
					pack.TargetFiles = unionStrings(pack.TargetFiles, []string{subject.Path})
					pack.TargetSymbols = unionStrings(pack.TargetSymbols, []string{subject.Symbol})
				}
			}
			if len(closingContracts[i]) > 0 && len(pack.CaseInvariants) == 0 {
				gap := fmt.Sprintf("Candidate %s contract could not be bound to current source.", cand.ID)
				pack.CoverageGaps = append(pack.CoverageGaps, gap)
				bundle.CoverageGaps = append(bundle.CoverageGaps, gap)
			}
			thin = append(thin, pack)
		}
	}
	merged := Merge(packs, thin)
	var contractPacks []artifacts.CasePack
	if doneContractsBound || runErr != nil {
		contractPacks = plannerBoundContractPacks(donePayload.CaseInvariants, cfg)
	} else {
		boundStandalone, contractErrors := bindPlannerContractsWithState(donePayload.CaseInvariants, cfg, state, &observations, executedToolFactRefs, nil)
		contractPacks = plannerBoundContractPacks(boundStandalone, cfg)
		bundle.Errors = append(bundle.Errors, contractErrors...)
	}
	merged = Merge(merged, contractPacks)
	for i := range merged {
		merged[i].ContractRequired = true
	}
	if cfg.StrictContractExit {
		var contracted []artifacts.CasePack
		for _, p := range merged {
			if len(p.CaseInvariants) > 0 {
				contracted = append(contracted, p)
				continue
			}
			bundle.CoverageGaps = append(bundle.CoverageGaps, fmt.Sprintf("Dropped uncontracted candidate case %s under strict contract-exit gate; only formalized CaseInvariantV2 obligations advance to downstream review.", p.CaseID))
		}
		merged = contracted
	}

	// Post-processing can add citation diagnostics; persist those as well.
	if err := runfs.WriteJSON(bundlePath, bundle); err != nil && runErr == nil {
		runErr = fmt.Errorf("write final evidence bundle: %w", err)
	}
	result := RunResult{Bundle: bundle, Err: runErr, Investigations: invs, CasePacks: merged}
	if checkpointEnabled && stable != nil {
		cp, err := cloneCheckpoint(stable)
		// An error can leave an uncommitted round. Keep its last persisted
		// budget reservation instead of replacing it with the older stable budget.
		if runErr != nil {
			var data []byte
			data, err = os.ReadFile(CheckpointPath(cfg.RunDir))
			if err == nil {
				err = json.Unmarshal(data, cp)
				cp.runDir = cfg.RunDir
			}
		}
		if err == nil {
			cp.TerminationReason = terminationReason
			if runErr == nil {
				cp.CoverageGaps = bundle.CoverageGaps
				cp.RunErrors = bundle.Errors
				cp.Completed = true
				cp.CachedResult = &CheckpointResult{Bundle: bundle, Investigations: invs, CasePacks: merged}
			}
			err = writeCheckpoint(cp)
		}
		if err != nil && result.Err == nil {
			result.Err = fmt.Errorf("persist final checkpoint: %w", err)
		}
	}
	return result
}

// processInvestigations converts the LLM's loosely-typed `done.investigations`
// entries (§7.5, §9.5) into grounded, persisted artifacts.TWEInvestigation
// and bounded artifacts.CasePack values. It never itself renders a
// vulnerability verdict — Build/Validate/BuildCasePack (internal/
// investigations) only classify, ground references, and bound the pack;
// see that package's doc comment. Each successfully built investigation is
// also appended to state.Investigations so a later planner pass in the same
// audit session (see internal/pipeline's --samples loop) sees it via
// BuildRoundPrompt's "ACTIVE TWE INVESTIGATIONS" section.
// executedToolFactRefs are the ToolFact paths this planner loop actually
// obtained from fact_layer_query. They are unioned into every investigation
// the same loop reported: the loop is shared, so the observation was in
// context for each one, and the done payload carries no per-investigation
// attribution that could narrow it. Once a TWE→operation mapping exists the
// union can be narrowed to the family the operation belongs to.
func processInvestigations(raw []map[string]any, cfg RunConfig, state *PlannerState, executedToolFactRefs []string) ([]artifacts.TWEInvestigation, []artifacts.CasePack, []artifacts.RoundError) {
	if len(raw) == 0 {
		return nil, nil, nil
	}

	var arch artifacts.ArchitectureModel
	if cfg.Architecture != nil {
		arch = *cfg.Architecture
	}
	validationIn := investigations.ValidationInput{
		Architecture: arch,
		Invariants:   cfg.Invariants,
		RepoRoot:     cfg.RepoRoot,
	}

	var invs []artifacts.TWEInvestigation
	var packs []artifacts.CasePack
	var errs []artifacts.RoundError
	for i, m := range raw {
		data, err := json.Marshal(m)
		if err != nil {
			errs = append(errs, artifacts.RoundError{Round: -1, Action: fmt.Sprintf("done.investigations[%d]", i), Error: fmt.Sprintf("remarshal: %v", err)})
			continue
		}
		var wire investigations.WireInvestigation
		if err := json.Unmarshal(data, &wire); err != nil {
			errs = append(errs, artifacts.RoundError{Round: -1, Action: fmt.Sprintf("done.investigations[%d]", i), Error: fmt.Sprintf("parse: %v", err)})
			continue
		}

		// Observation IDs identify recorded tool output, not a JSON file.
		// Keep the namespaces separate before filesystem validation and retain
		// a diagnostic so an invalid citation cannot disappear silently.
		var keptRefs []string
		var automaticRefs []string
		for _, ref := range executedToolFactRefs {
			// A presented batch prescan is a clue, not automatically evidence
			// for every unrelated investigation. Attach it only when cited or
			// explicitly bound to the investigation's lead/contract.
			if cfg.PreScannedTaint == nil || ref != cfg.PreScannedTaint.FactRef {
				automaticRefs = append(automaticRefs, ref)
			}
		}
		for _, ref := range unionStrings(wire.ToolFactRefs, automaticRefs) {
			if strings.HasPrefix(strings.TrimSpace(ref), "obs:") {
				errs = append(errs, artifacts.RoundError{Round: -1, Action: fmt.Sprintf("done.investigations[%d].tool_fact_refs", i), Error: fmt.Sprintf("observation reference %q is not a ToolFact file; use reason_fact_refs for observations", ref)})
				continue
			}
			keptRefs = append(keptRefs, ref)
		}
		wire.ToolFactRefs = keptRefs
		if len(wire.CaseInvariants) > 0 {
			var accepted []artifacts.CaseInvariantV2
			if state != nil {
				accepted = state.Contracts
			}
			var rejected int
			wire.CaseInvariants, rejected = acceptedContractCopies(wire.CaseInvariants, accepted)
			if rejected > 0 {
				errs = append(errs, artifacts.RoundError{Round: -1, Action: fmt.Sprintf("done.investigations[%d].case_invariants", i), Error: fmt.Sprintf("omitted %d contract draft(s) that were not accepted during the planner loop", rejected)})
			}
		}
		inv := investigations.Build(wire)
		// Union before Validate so an executed ref is subject to the same
		// on-disk resolution check as a model-reported one.
		// Only what this loop executed. The pipeline used to union in
		// ToolFacts it had collected before the loop started, from queries
		// chosen by the run's invariants — so every investigation, however
		// the Planner reached it, shipped evidence the old invariant had
		// selected. Closing that channel is half of what makes a lead the
		// Planner's own.
		inv, _ = investigations.Validate(inv, validationIn)

		if cfg.RunDir != "" {
			if _, err := investigations.Persist(cfg.RunDir, inv); err != nil {
				errs = append(errs, artifacts.RoundError{Round: -1, Action: "investigations.Persist:" + inv.InvestigationID, Error: err.Error()})
			}
		}

		invs = append(invs, inv)
		if state != nil {
			state.AddInvestigations([]artifacts.TWEInvestigation{inv})
		}

		playbook := cfg.TWEPlaybooks[firstOrEmpty(inv.TWEIDs)]
		pack := investigations.BuildCasePack(inv, investigations.CasePackInput{
			CaseID:               inv.InvestigationID,
			Focus:                cfg.Profile.Focus,
			CommonDefenses:       playbook.CommonDefenses,
			CommonFalsePositives: playbook.CommonFalsePositives,
		})
		pack.ContractRequired = true
		// Packs are NOT written here. Run merges them with the
		// candidate-derived packs and returns the combined list; the
		// pipeline writes it through planner.Write once per run, so
		// numbering across both halves — and across --samples passes —
		// stays consistent on the case-*.json glob consumers use.
		packs = append(packs, pack)
	}
	return invs, packs, errs
}

// toolFactRefFrom pulls the tool_fact_ref out of a fact_layer_query
// observation (actions.factLayerQueryOutput). An unparseable or ref-less
// observation yields "" — the handler only omits the field on a path that
// already reported OK=false, so there is nothing to record and nothing to
// report twice.
func toolFactRefFrom(output string) string {
	var obs struct {
		ToolFactRef string `json:"tool_fact_ref"`
	}
	if err := json.Unmarshal([]byte(output), &obs); err != nil {
		return ""
	}
	return obs.ToolFactRef
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... (truncated)"
}

// trackObservedPaths extracts repo-relative file paths from action
// args (for path-taking actions) and action outputs (for ripgrep),
// storing them in the observed set. The set is injected into the
// force-done prompt as the allowed whitelist for candidate paths.
func trackObservedPaths(actionName string, argsJSON json.RawMessage, output, repoRoot string, observed map[string]bool) {
	// Case 1: path-taking actions record their arg directly.
	switch actionName {
	case "list_dir", "read_file", "tree_sitter_outline":
		var args struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(argsJSON, &args); err == nil && args.Path != "" {
			// Normalize and only keep if it actually exists.
			if norm, ok := normalizePath(args.Path, repoRoot); ok {
				observed[norm] = true
			}
		}
	}

	// Case 2: ripgrep output contains one match per line in the form
	// "/abs/path/to/file.rs:LINE:content". Extract the path prefix.
	if actionName == "ripgrep" && output != "" {
		for _, line := range strings.Split(output, "\n") {
			// Find the first colon that isn't part of a Windows drive.
			idx := strings.Index(line, ":")
			if idx <= 0 {
				continue
			}
			full := line[:idx]
			rel, err := filepath.Rel(repoRoot, full)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			// Only record if it still exists (ripgrep already proved it did).
			if norm, ok := normalizePath(rel, repoRoot); ok {
				observed[norm] = true
			}
		}
	}
}

// convertCandidates converts the LLM's loosely-typed done payload
// into typed artifacts.Candidate, filtering out paths that do not
// exist on disk under repoRoot. Candidates whose entire path list
// disappears are dropped. Returns the surviving candidates plus a
// diagnostic list of what was dropped so the caller can surface
// path-hallucination problems in the evidence bundle's Errors.
func convertCandidates(raw []map[string]any, repoRoot string) ([]artifacts.Candidate, []artifacts.RoundError) {
	out := make([]artifacts.Candidate, 0, len(raw))
	var dropped []artifacts.RoundError
	for i, m := range raw {
		c := artifacts.Candidate{
			ID: fmt.Sprintf("candidate-%03d", i+1),
		}
		if v, ok := m["id"].(string); ok && v != "" {
			c.ID = v
		}
		if v, ok := m["kind"].(string); ok {
			c.Kind = v
		}
		if v, ok := m["priority"].(string); ok {
			c.Priority = v
		}

		// Path validation: drop any path that doesn't resolve to a
		// real file under repoRoot.
		rawPaths := stringSlice(m["paths"])
		c.Paths = make([]string, 0, len(rawPaths))
		for _, p := range rawPaths {
			normalized, exists := normalizePath(p, repoRoot)
			if !exists {
				dropped = append(dropped, artifacts.RoundError{
					Round:  -1,
					Action: "done.candidate." + c.ID,
					Error:  fmt.Sprintf("hallucinated path: %q (not found under %s)", p, repoRoot),
				})
				continue
			}
			c.Paths = append(c.Paths, normalized)
		}
		// If all paths were dropped, drop the whole candidate.
		if len(c.Paths) == 0 {
			dropped = append(dropped, artifacts.RoundError{
				Round:  -1,
				Action: "done.candidate." + c.ID,
				Error:  "candidate dropped: all paths were hallucinated",
			})
			continue
		}

		c.Symbols = stringSlice(m["symbols"])
		c.WhySelected = stringSlice(m["why_selected"])
		c.EvidenceRefs = stringSlice(m["evidence_refs"])
		if v, ok := m["sink_category"].(string); ok {
			c.SinkCategory = v
		}
		if v, ok := m["confidence"].(float64); ok {
			c.Confidence = v
		}
		out = append(out, c)
	}
	return out, dropped
}

// normalizePath tries to resolve a path the LLM produced to a real
// file under repoRoot. The LLM occasionally adds a spurious leading
// component (e.g. "mobilecoin/attest/x.rs" when the repo basename is
// mobilecoin and the real file is "attest/x.rs"), or prefixes with
// the absolute repo root path, or abbreviates directory names (e.g.
// "sgx/svc/" when the real dir is "sgx/service/"). We try several
// transformations; the first one that corresponds to a real file
// wins. Returns (normalizedPath, exists).
func normalizePath(p, repoRoot string) (string, bool) {
	if repoRoot == "" {
		return p, false
	}
	tryList := []string{p}
	// Strip absolute repo root prefix if the LLM included it.
	if strings.HasPrefix(p, repoRoot+string(os.PathSeparator)) {
		tryList = append(tryList, strings.TrimPrefix(p, repoRoot+string(os.PathSeparator)))
	}
	// Strip leading repo basename if the LLM pseudo-prefixed it.
	base := filepath.Base(repoRoot)
	if base != "" && base != "." && strings.HasPrefix(p, base+"/") {
		tryList = append(tryList, strings.TrimPrefix(p, base+"/"))
	}
	for _, cand := range tryList {
		full := filepath.Join(repoRoot, cand)
		if _, err := os.Stat(full); err == nil {
			return cand, true
		}
	}
	return p, false
}

// stringSlice normalizes an "any" field from the LLM's done payload
// into a []string. Tolerates both shapes the LLM produces in practice:
//   - a proper JSON array of strings
//   - a single JSON string (the LLM sometimes collapses single-item
//     arrays into a bare string)
func stringSlice(v any) []string {
	switch typed := v.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func failedResult(cfg RunConfig, msg, reason string) RunResult {
	return RunResult{
		Bundle: &artifacts.EvidenceBundle{
			SchemaVersion: "teecheck.evidence_bundle.v1",
			RunID:         cfg.RunID,
			PlannerMeta: artifacts.PlannerMeta{
				TerminationReason: reason,
			},
		},
		Err: fmt.Errorf("%s", msg),
	}
}

func unresolvedSampleLeads(state *PlannerState, runID string, sampleIndex int) []string {
	if state == nil {
		return nil
	}
	var out []string
	for _, lead := range state.AuditLeads {
		if lead.RunID != runID || lead.SampleIndex != sampleIndex {
			continue
		}
		switch lead.State {
		case artifacts.LeadStateOpen, artifacts.LeadStateExpanded:
			out = append(out, lead.LeadID)
		case artifacts.LeadStateFormalized:
			if !leadBackedByAcceptedContract(lead, state.Contracts) {
				out = append(out, lead.LeadID)
			}
		}
	}
	return out
}

func cloneLeadsSlice(in []artifacts.AuditLead) []artifacts.AuditLead {
	if len(in) == 0 {
		return nil
	}
	out := make([]artifacts.AuditLead, len(in))
	for i := range in {
		out[i] = cloneLead(in[i])
	}
	return out
}

func allowedInConvergenceFreeze(action string) bool {
	switch action {
	case "read_file", ActionUpdateLead, ActionFormalizeContract, ActionCloseLead, "done":
		return true
	default:
		return false
	}
}
