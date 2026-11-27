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
	"sync"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

const (
	scoutMaxRounds        = 5
	investigatorMaxRounds = 6
	closuresPerScout      = 12
	maxShardedLeads       = 10
)

// HasBoundaryTopology reports whether this run has a non-empty deterministic
// 3-hop boundary topology that sharded scouting can partition.
func HasBoundaryTopology(runDir string) bool {
	if runDir == "" {
		return false
	}
	var topo artifacts.BoundaryTopology
	if err := runfs.ReadJSON(runfs.BoundaryTopologyPath(runDir), &topo); err != nil {
		return false
	}
	return len(topo.EntryClosures) > 0
}

type scoutDossier struct {
	Bucket   string
	Closures []artifacts.EntryClosure
	Bridges  []artifacts.StructFieldBridge
}

func scoutPathPriorityTier(path string) int {
	p := strings.ToLower(strings.TrimPrefix(filepath.ToSlash(path), "./"))
	// Tier 0: platform board glue, generic third-party compression/FDT, tests, asm-defines.
	if strings.Contains(p, "/plat-") || strings.HasPrefix(p, "plat-") ||
		strings.Contains(p, "/lib/zlib/") || strings.Contains(p, "/lib/libfdt/") ||
		strings.Contains(p, "asm-defines") || strings.Contains(p, "asm_defines") ||
		strings.Contains(p, "_test.") || strings.Contains(p, "/test/") || strings.Contains(p, "/tests/") {
		return 0
	}
	// Tier 2: core trust-boundary, syscall, SMC/entry, MMU/mobj, TA loader, PTA/enclave runtime.
	if strings.HasPrefix(p, "core/tee/") ||
		strings.HasPrefix(p, "core/kernel/") ||
		strings.HasPrefix(p, "core/mm/") ||
		strings.HasPrefix(p, "core/pta/") ||
		strings.HasPrefix(p, "ldelf/") ||
		strings.Contains(p, "/tee/") ||
		strings.Contains(p, "/kernel/") ||
		strings.Contains(p, "/mm/") ||
		strings.HasPrefix(p, "enclave/") ||
		strings.HasPrefix(p, "trusted/") {
		return 2
	}
	// Tier 1: drivers, crypto, TAs, other source modules.
	return 1
}

func symbolIDPath(id artifacts.SymbolID) string {
	parts := strings.SplitN(string(id), ":", 4)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func selectScoutDossiers(topo artifacts.BoundaryTopology, perBucket int) []scoutDossier {
	if perBucket <= 0 {
		perBucket = closuresPerScout
	}
	byRoot := make(map[artifacts.SymbolID]artifacts.EntryClosure, len(topo.EntryClosures))
	for _, c := range topo.EntryClosures {
		byRoot[c.RootSymbolID] = c
	}

	// Build structural bridge density maps from named cross-file/cross-module StructFieldBridges.
	fileBridgeScore := map[string]int{}
	symBridgeScore := map[artifacts.SymbolID]int{}
	fileBridges := map[string][]artifacts.StructFieldBridge{}
	for _, br := range topo.StructFieldBridges {
		if strings.HasPrefix(br.Field, "(unnamed ") {
			continue
		}
		seenFiles := map[string]bool{}
		for _, id := range br.DirectWriters {
			symBridgeScore[id] += 2
			if fp := symbolIDPath(id); fp != "" {
				seenFiles[fp] = true
			}
		}
		for _, id := range br.NonWriteAccessors {
			symBridgeScore[id] += 1
			if fp := symbolIDPath(id); fp != "" {
				seenFiles[fp] = true
			}
		}
		weight := 1
		if br.CrossModule {
			weight = 3
		} else if len(seenFiles) >= 2 {
			weight = 2
		}
		for fp := range seenFiles {
			fileBridgeScore[fp] += weight
			if len(fileBridges[fp]) < 12 {
				fileBridges[fp] = append(fileBridges[fp], br)
			}
		}
	}

	scoreClosure := func(c artifacts.EntryClosure) int {
		score := scoutPathPriorityTier(c.RootPath) * 1000
		score += fileBridgeScore[c.RootPath] * 4
		score += symBridgeScore[c.RootSymbolID] * 8
		score += len(c.DirectFieldWrites) * 3
		members := len(c.Members)
		if members > 12 {
			members = 12
		}
		score += members * 2
		for _, sig := range c.Signals {
			switch sig {
			case "buffer_length_parameters":
				score += 20
			case "global_function_pointer_initializer", "entry_symbol_name":
				score += 12
			}
		}
		return score
	}

	assigned := map[artifacts.SymbolID]bool{}
	globalFileCount := map[string]int{}
	var dossiers []scoutDossier
	for _, part := range topo.SurfacePartitions {
		if part.ClosureCount == 0 {
			continue
		}
		type scoredClosure struct {
			c     artifacts.EntryClosure
			score int
		}
		candidates := make([]scoredClosure, 0, len(part.RootSymbolIDs))
		for _, id := range part.RootSymbolIDs {
			if assigned[id] {
				continue
			}
			c, ok := byRoot[id]
			if !ok {
				continue
			}
			candidates = append(candidates, scoredClosure{c: c, score: scoreClosure(c)})
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score > candidates[j].score
			}
			return candidates[i].c.RootSymbolID < candidates[j].c.RootSymbolID
		})

		// Pass 1: enforce strict per-file diversity (max 1 per shard, max 2 across all shards).
		var picked []artifacts.EntryClosure
		shardFileCount := map[string]int{}
		for _, sc := range candidates {
			if len(picked) >= perBucket {
				break
			}
			if shardFileCount[sc.c.RootPath] >= 1 || globalFileCount[sc.c.RootPath] >= 2 {
				continue
			}
			assigned[sc.c.RootSymbolID] = true
			shardFileCount[sc.c.RootPath]++
			globalFileCount[sc.c.RootPath]++
			picked = append(picked, sc.c)
		}
		// Pass 2: fill remaining slots if a small repo has fewer distinct files than perBucket.
		for _, sc := range candidates {
			if len(picked) >= perBucket {
				break
			}
			if assigned[sc.c.RootSymbolID] {
				continue
			}
			assigned[sc.c.RootSymbolID] = true
			globalFileCount[sc.c.RootPath]++
			picked = append(picked, sc.c)
		}
		if len(picked) == 0 {
			continue
		}

		// Collect top named cross-file/cross-module bridges touching picked files or written fields.
		writtenFields := map[string]bool{}
		pickedFiles := map[string]bool{}
		for _, c := range picked {
			pickedFiles[c.RootPath] = true
			for _, f := range c.DirectFieldWrites {
				writtenFields[f] = true
			}
		}
		seenBridge := map[string]bool{}
		var bridges []artifacts.StructFieldBridge
		for _, br := range topo.StructFieldBridges {
			if strings.HasPrefix(br.Field, "(unnamed ") || seenBridge[br.Field] {
				continue
			}
			if writtenFields[br.Field] && (br.CrossModule || len(br.NonWriteAccessors) > 0) {
				seenBridge[br.Field] = true
				bridges = append(bridges, br)
				if len(bridges) >= 10 {
					break
				}
			}
		}
		if len(bridges) < 10 {
			for fp := range pickedFiles {
				for _, br := range fileBridges[fp] {
					if seenBridge[br.Field] {
						continue
					}
					if br.CrossModule || len(br.NonWriteAccessors) > 0 {
						seenBridge[br.Field] = true
						bridges = append(bridges, br)
						if len(bridges) >= 10 {
							break
						}
					}
				}
				if len(bridges) >= 10 {
					break
				}
			}
		}

		dossiers = append(dossiers, scoutDossier{
			Bucket:   part.Bucket,
			Closures: picked,
			Bridges:  bridges,
		})
	}
	return dossiers
}

func formatScoutDossier(d scoutDossier, prescan *PreScannedTaint, includePrescan bool) string {
	var b strings.Builder
	if includePrescan && prescan != nil {
		b.WriteString(preScannedTaintBlock(prescan))
	}
	fmt.Fprintf(&b, "=== BOUNDARY SCOUT SHARD: bucket=%s (%d assigned core closures) ===\n", d.Bucket, len(d.Closures))
	b.WriteString("Inspect the highest-risk trust-boundary closures below by calling `read_file` on their root and 1..3-hop helper files.\n")
	b.WriteString("As soon as source code reveals a concrete security question (missing bounds/auth/state/lifecycle check), call `open_audit_lead` using the exact `id=...` (lang:file:line:sig) for `target_symbol_ids` and the full `ref=obs:...` string for `reason_fact_refs`.\n")
	b.WriteString("Do NOT waste rounds on `get_repository_card` or `list_modules` — start reading source immediately. Call `done` once you have inspected several distinct files and opened 1-2 strong leads (or confirmed none).\n\n")
	for i, c := range d.Closures {
		fmt.Fprintf(&b, "%d. %s  %s:%d-%d  id=%s  signals=%s\n",
			i+1, c.RootName, c.RootPath, c.RootStartLine, c.RootEndLine, c.RootSymbolID, strings.Join(c.Signals, ","))
		if len(c.Members) > 1 {
			var hops []string
			for _, m := range c.Members {
				if m.Hop == 0 {
					continue
				}
				hops = append(hops, fmt.Sprintf("%s(%s:%d,hop=%d)", m.Name, m.Path, m.Line, m.Hop))
				if len(hops) >= 6 {
					break
				}
			}
			if len(hops) > 0 {
				fmt.Fprintf(&b, "   callees(1..3-hop): %s\n", strings.Join(hops, ", "))
			}
		}
		if len(c.DirectFieldWrites) > 0 {
			w := c.DirectFieldWrites
			if len(w) > 6 {
				w = w[:6]
			}
			fmt.Fprintf(&b, "   direct_field_writes: %s\n", strings.Join(w, ", "))
		}
	}
	if len(d.Bridges) > 0 {
		b.WriteString("\nRelevant cross-function struct field bridges (use `get_struct_flows` for full reader/writer lists):\n")
		for _, br := range d.Bridges {
			fmt.Fprintf(&b, "  - %s: writers=%d non_write_accessors=%d cross_module=%v\n",
				br.Field, len(br.DirectWriters), len(br.NonWriteAccessors), br.CrossModule)
		}
	}
	b.WriteByte('\n')
	return b.String()
}

type shardedCoordinator struct {
	mu                   sync.Mutex
	cfg                  RunConfig
	symbolCatalog        []artifacts.SymbolID
	state                *PlannerState
	recon                *ReconState
	budget               Budget
	loopStartedAt        time.Time
	observations         ObservationSet
	observedPaths        map[string]bool
	executedToolFactRefs []string
	coverageGaps         []string
	runErrors            []artifacts.RoundError
	completedScouts      map[string]bool
	completedLeads       map[string]bool
	failedShards         []string
	triageBatches        map[int]TriageBatchRecord
	triageSummary        *TriageSummary
	scoutProposals       []scoutLeadProposal
	reservedTotal        int
	reservedRecon        int
	reservedInvest       int
	mutatingRounds       map[int]bool
	nextRound            int
	roundsLog            string
	checkpointEnabled    bool
	topologyRequired     bool
	treeHash             string
	binaryHash           string
	policyRefusalErr     error
	cancelAll            context.CancelFunc
}

type scoutLeadProposal struct {
	Bucket        string
	PrimaryPath   string
	PrimarySymbol string
	PrimaryID     artifacts.SymbolID
	Question      string
	CanonArgs     json.RawMessage
	RoundNum      int
}

func (sc *shardedCoordinator) allocRound(isScout bool) int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if isScout && sc.budget.ReconExhausted() || !isScout && sc.budget.RemainingRounds() == 0 {
		return 0
	}
	sc.nextRound++
	if isScout {
		sc.budget.ConsumeReconRound()
	} else {
		sc.budget.ConsumeRound()
	}
	return sc.nextRound
}

func (sc *shardedCoordinator) reserveShardTokens(inputTokens int, isScout, isFinal bool, roleMaxOut, minOut int) (outBudget int, reserved int, ok bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	// Compute allowance against effective budget reduced by in-flight reservations.
	eff := sc.budget
	eff.TokensUsed += sc.reservedTotal
	if isScout {
		eff.ReconTokensUsed += sc.reservedRecon
	} else {
		eff.InvestigationTokensUsed += sc.reservedInvest
	}
	allow := eff.OutputAllowance(inputTokens, isScout, isFinal)
	limit := roleMaxOut
	if limit <= 0 {
		limit = 32768
	}
	if allow == UnlimitedOutputAllowance || allow > limit {
		outBudget = limit
	} else {
		outBudget = allow
	}
	if outBudget < minOut {
		return outBudget, 0, false
	}
	reserved = inputTokens + outBudget
	sc.reservedTotal += reserved
	if isScout {
		sc.reservedRecon += reserved
	} else {
		sc.reservedInvest += reserved
	}
	return outBudget, reserved, true
}

func (sc *shardedCoordinator) settleShardTokens(reserved, actual int, isScout bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.reservedTotal -= reserved
	if sc.reservedTotal < 0 {
		sc.reservedTotal = 0
	}
	if isScout {
		sc.reservedRecon -= reserved
		if sc.reservedRecon < 0 {
			sc.reservedRecon = 0
		}
	} else {
		sc.reservedInvest -= reserved
		if sc.reservedInvest < 0 {
			sc.reservedInvest = 0
		}
	}
	if actual > 0 {
		sc.budget.ConsumePhaseTokens(actual, isScout)
	}
}

func (sc *shardedCoordinator) wallClockExhausted() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.budget.WallClock > 0 && time.Since(sc.budget.startedAt) >= sc.budget.WallClock
}

func (sc *shardedCoordinator) wallClockDeadline() (time.Time, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.budget.WallClock <= 0 {
		return time.Time{}, false
	}
	return sc.budget.startedAt.Add(sc.budget.WallClock), true
}

func (sc *shardedCoordinator) consumeTokens(total int, isScout bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.budget.ConsumePhaseTokens(total, isScout)
}

func (sc *shardedCoordinator) consumeTaintQuery() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.budget.ConsumeTaintQuery()
}

func (sc *shardedCoordinator) recordShardFailure(label, reason string, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.recordShardFailureLocked(label, reason, err)
}

func (sc *shardedCoordinator) recordShardFailureLocked(label, reason string, err error) {
	sc.failedShards = append(sc.failedShards, label+":"+reason)
	msg := fmt.Sprintf("Shard %s failed (%s)", label, reason)
	if err != nil {
		msg += ": " + err.Error()
	}
	sc.coverageGaps = unionStrings(sc.coverageGaps, []string{msg})
	sc.runErrors = append(sc.runErrors, artifacts.RoundError{Round: -1, Action: "shard:" + label, Error: msg})
	if err != nil && llm.IsPolicyRefusal(err) && sc.policyRefusalErr == nil {
		sc.policyRefusalErr = err
		if sc.cancelAll != nil {
			sc.cancelAll()
		}
	}
}

func (sc *shardedCoordinator) saveCheckpointLocked(completed bool, termination string, cached *CheckpointResult) error {
	if !sc.checkpointEnabled {
		return nil
	}
	// A different worker may still be applying actions from a round that has
	// not reached rounds.jsonl. Preserve the last consistent state/journals,
	// updating only spent/reserved budget until that round commits.
	if len(sc.mutatingRounds) > 0 {
		return sc.saveBudgetCheckpointLocked()
	}
	currentTree, err := sourcehash.TreeExcluding(sc.cfg.RepoRoot, []string{sc.cfg.RunDir})
	if err != nil {
		return err
	}
	if currentTree != sc.treeHash {
		return fmt.Errorf("source contents changed during sharded planner run")
	}
	paths := make([]string, 0, len(sc.observedPaths))
	for p := range sc.observedPaths {
		paths = append(paths, p)
	}
	hashes, err := sourcehash.Files(sc.cfg.RepoRoot, paths)
	if err != nil {
		return err
	}
	scouts := make([]string, 0, len(sc.completedScouts))
	for k := range sc.completedScouts {
		scouts = append(scouts, k)
	}
	sort.Strings(scouts)
	doneLeads := make([]string, 0, len(sc.completedLeads))
	for k := range sc.completedLeads {
		doneLeads = append(doneLeads, k)
	}
	sort.Strings(doneLeads)
	lastCommittedRound := 0
	for _, round := range sc.state.Rounds {
		lastCommittedRound = max(lastCommittedRound, round.Round)
	}

	cp := &Checkpoint{
		SchemaVersion:        checkpointVersion,
		RunID:                sc.cfg.RunID,
		SampleIndex:          sc.cfg.SampleIndex,
		Profile:              sc.cfg.Profile,
		ConfigSHA256:         checkpointConfigHash(sc.cfg),
		ExecutableSHA256:     sc.binaryHash,
		TreeContentHash:      sc.treeHash,
		ObservedFileHashes:   hashes,
		LastCommittedRound:   lastCommittedRound,
		State:                sc.state,
		Recon:                snapshotRecon(sc.recon),
		Budget:               sc.budget,
		ElapsedNanos:         time.Since(sc.loopStartedAt).Nanoseconds(),
		ObservedPaths:        sc.observedPaths,
		Observations:         sc.observations.ok,
		Leads:                cloneLeadsSlice(sc.state.AuditLeads),
		ExecutedToolFactRefs: append([]string(nil), sc.executedToolFactRefs...),
		CoverageGaps:         append([]string(nil), sc.coverageGaps...),
		RunErrors:            append([]artifacts.RoundError(nil), sc.runErrors...),
		TerminationReason:    termination,
		AvoidPaths:           sc.cfg.AvoidPaths,
		Journals:             map[string]JournalBoundary{},
		Sharded: &ShardedCheckpoint{
			CompletedScouts:  scouts,
			CompletedLeads:   doneLeads,
			FailedShards:     append([]string(nil), sc.failedShards...),
			TriageBatches:    cloneTriageBatches(sc.triageBatches),
			TriageSummary:    sc.triageSummary,
			NextRound:        sc.nextRound,
			ScoutProposals:   append([]scoutLeadProposal(nil), sc.scoutProposals...),
			ReservedRecon:    sc.reservedRecon,
			ReservedInvest:   sc.reservedInvest,
			TopologyRequired: sc.topologyRequired,
		},
		Completed:    completed,
		CachedResult: cached,
		runDir:       sc.cfg.RunDir,
	}
	for _, name := range checkpointJournalNames {
		boundary, err := journalBoundary(filepath.Join(sc.cfg.RunDir, filepath.FromSlash(name)), -1)
		if err != nil {
			return err
		}
		cp.Journals[name] = boundary
	}
	cp.EventOffset = cp.Journals["events.jsonl"].Offset
	return writeCheckpoint(cp)
}

// saveBudgetCheckpointLocked retains the last stable source/lead/journal
// boundary while making an LLM reservation durable before dispatch. A crash
// with unreported usage conservatively spends the outstanding reservation.
func (sc *shardedCoordinator) saveBudgetCheckpointLocked() error {
	if !sc.checkpointEnabled {
		return nil
	}
	var cp Checkpoint
	if err := runfs.ReadJSON(CheckpointPath(sc.cfg.RunDir), &cp); err != nil {
		return err
	}
	if cp.Sharded == nil {
		return fmt.Errorf("cannot update a non-sharded checkpoint budget")
	}
	cp.runDir = sc.cfg.RunDir
	cp.Budget = sc.budget
	cp.ElapsedNanos = time.Since(sc.loopStartedAt).Nanoseconds()
	cp.Sharded.NextRound = sc.nextRound
	cp.Sharded.ReservedRecon = sc.reservedRecon
	cp.Sharded.ReservedInvest = sc.reservedInvest
	return writeCheckpoint(&cp)
}

// RunSharded executes Stage 2 decoupled breadth/depth planning:
//  1. Parallel BoundaryScouts (fast ScoutClient) sweep non-overlapping 3-hop
//     boundary closures across the 4 structural buckets and open grounded leads.
//  2. Parallel LeadInvestigators (strong Client) each investigate one lead in
//     isolation with preloaded context and formalize or close it.
//
// Any shard error, timeout, or unresolved lead propagates honestly as
// incomplete coverage (never masked as `sharded_done` / `satisfied`).
func RunSharded(ctx context.Context, cfg RunConfig) RunResult {
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
	inheritScoutTemperature := cfg.ScoutClient == nil && cfg.ScoutModel == "" && cfg.ScoutMaxOutputTokens == 0 && cfg.ScoutTemperature == 0
	if cfg.ScoutClient == nil {
		cfg.ScoutClient = cfg.Client
	}
	if cfg.ScoutModel == "" {
		cfg.ScoutModel = cfg.Model
	}
	if cfg.ScoutMaxOutputTokens <= 0 {
		cfg.ScoutMaxOutputTokens = cfg.MaxOutputTokens
	}
	if inheritScoutTemperature {
		cfg.ScoutTemperature = cfg.Temperature
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	if workers > 4 {
		workers = 4
	}

	var topo artifacts.BoundaryTopology
	hasTopo := cfg.RunDir != "" && runfs.ReadJSON(runfs.BoundaryTopologyPath(cfg.RunDir), &topo) == nil && len(topo.EntryClosures) > 0
	if !hasTopo && !HasCoreEntrySurfaces(cfg.RepoRoot) {
		if cfg.Resume {
			return failedResult(cfg, "sharded checkpoint input topology and entry surfaces are unavailable", "resume_error")
		}
		return Run(ctx, cfg)
	}

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
		if resumed.Sharded == nil {
			return failedResult(cfg, "cannot restore a monolithic checkpoint as a sharded planner", "resume_error")
		}
		if resumed.Sharded.TopologyRequired && !hasTopo {
			return failedResult(cfg, "boundary topology required by the sharded checkpoint is unavailable", "resume_error")
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
	projectMap, _ := loadProjectMap(cfg.RunDir)
	recon := NewReconState(ReconModeFor(projectMap)).WithTotals(
		len(projectMap.Modules), totalFunctions(projectMap), projectMap.Repository.FileCount).
		WithEntrySurfaces(projectMap.Capabilities.EntrySurfaces, projectMap.EntrySurfaces)
	// Sharded scouts start directly with pre-computed boundary dossiers rather
	// than spending rounds on monolithic card-counting gates.
	recon.SkipReconnaissance()

	shardedCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	sc := &shardedCoordinator{
		cfg:               cfg,
		state:             NewState(cfg.RunID),
		recon:             recon,
		budget:            cfg.Budget,
		loopStartedAt:     loopStartedAt,
		observedPaths:     map[string]bool{},
		completedScouts:   map[string]bool{},
		completedLeads:    map[string]bool{},
		triageBatches:     map[int]TriageBatchRecord{},
		roundsLog:         runfs.RoundsLogPath(cfg.RunDir),
		checkpointEnabled: cfg.RunDir != "" && cfg.RepoRoot != "",
		topologyRequired:  hasTopo,
		cancelAll:         cancelAll,
	}

	if resumed != nil {
		sc.state = resumed.State
		sc.recon = resumed.Recon.restore()
		sc.budget = resumed.Budget
		sc.budget.startedAt = time.Now().Add(-time.Duration(resumed.ElapsedNanos))
		sc.loopStartedAt = sc.budget.startedAt
		sc.observedPaths = resumed.ObservedPaths
		if sc.observedPaths == nil {
			sc.observedPaths = map[string]bool{}
		}
		sc.observations.ok = resumed.Observations
		sc.executedToolFactRefs = resumed.ExecutedToolFactRefs
		sc.coverageGaps = resumed.CoverageGaps
		sc.runErrors = resumed.RunErrors
		sc.treeHash, sc.binaryHash = resumed.TreeContentHash, resumed.ExecutableSHA256
		if resumed.Sharded != nil {
			sc.budget.ConsumePhaseTokens(resumed.Sharded.ReservedRecon, true)
			sc.budget.ConsumePhaseTokens(resumed.Sharded.ReservedInvest, false)
			sc.nextRound = resumed.Sharded.NextRound
			sc.scoutProposals = append([]scoutLeadProposal(nil), resumed.Sharded.ScoutProposals...)
			for _, b := range resumed.Sharded.CompletedScouts {
				sc.completedScouts[b] = true
			}
			for _, lid := range resumed.Sharded.CompletedLeads {
				if isLeadResolvedLocked(sc.state, cfg.RunID, cfg.SampleIndex, lid) {
					sc.completedLeads[lid] = true
				}
			}
			if len(resumed.Sharded.TriageBatches) > 0 {
				sc.triageBatches = cloneTriageBatches(resumed.Sharded.TriageBatches)
			}
			sc.triageSummary = resumed.Sharded.TriageSummary
			// Clear prior run's transient shard failures on resume so retried & succeeded shards
			// are not permanently tainted by earlier failures.
		}
	} else if sc.checkpointEnabled {
		var err error
		sc.treeHash, err = sourcehash.TreeExcluding(cfg.RepoRoot, []string{cfg.RunDir})
		if err != nil {
			return failedResult(cfg, "fingerprint source: "+err.Error(), "checkpoint_error")
		}
		sc.binaryHash, err = executableHash()
		if err != nil {
			return failedResult(cfg, err.Error(), "checkpoint_error")
		}
	}

	sc.state.PreScannedTaint = cfg.PreScannedTaint
	if cfg.PreScannedTaint != nil {
		sc.coverageGaps = unionStrings(sc.coverageGaps, cfg.PreScannedTaint.CoverageGaps)
		seedPreScannedTaint(cfg.PreScannedTaint, prescanFact, &sc.observations, &sc.executedToolFactRefs)
	}
	if resumed == nil {
		sc.mu.Lock()
		err := sc.saveCheckpointLocked(false, "", nil)
		sc.mu.Unlock()
		if err != nil {
			return failedResult(cfg, "write initial sharded checkpoint: "+err.Error(), "checkpoint_error")
		}
	}

	sc.symbolCatalog = buildScoutSymbolCatalog(cfg.RunDir, topo)

	// Phase 0: Bounded stratified entry triage (CodeQL-independent, resumable per batch).
	sc.mu.Lock()
	triageDone := sc.completedScouts["__entry_triage__"]
	sc.mu.Unlock()
	if !triageDone {
		_, allBatchesOK := sc.runEntryTriage(shardedCtx, topo, workers)
		sc.mu.Lock()
		if allBatchesOK {
			sc.completedScouts["__entry_triage__"] = true
		}
		if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
			sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
		}
		sc.mu.Unlock()
	}

	// Phase A: Concurrent BoundaryScouts across the structural buckets.
	dossiers := selectScoutDossiers(topo, closuresPerScout)
	sc.mu.Lock()
	triageLeadCount := len(sc.state.AuditLeads)
	sc.mu.Unlock()
	if triageLeadCount >= entryTriageMaxLeads && len(dossiers) > 2 {
		dossiers = dossiers[:2]
	}
	fmt.Fprintf(os.Stdout, "[planner/sharded] starting %d BoundaryScout shard(s) (workers=%d, scout_model=%s)\n",
		len(dossiers), workers, cfg.ScoutModel)

	sem := make(chan struct{}, workers)
	var scoutWG sync.WaitGroup
	var scoutsSucceeded int
	var scoutsSucceededMu sync.Mutex

	for idx, dossier := range dossiers {
		sc.mu.Lock()
		alreadyDone := sc.completedScouts[dossier.Bucket]
		sc.mu.Unlock()
		if alreadyDone {
			scoutsSucceededMu.Lock()
			scoutsSucceeded++
			scoutsSucceededMu.Unlock()
			continue
		}
		scoutWG.Add(1)
		go func(i int, d scoutDossier) {
			defer scoutWG.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-shardedCtx.Done():
				sc.recordShardFailure("scout:"+d.Bucket, "cancelled", shardedCtx.Err())
				return
			}
			ok := sc.runBoundaryScout(shardedCtx, d, i == 0)
			if ok {
				scoutsSucceededMu.Lock()
				scoutsSucceeded++
				scoutsSucceededMu.Unlock()
				sc.mu.Lock()
				sc.completedScouts[d.Bucket] = true
				if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
					sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
				}
				sc.mu.Unlock()
			}
		}(idx, dossier)
	}
	scoutWG.Wait()
	sc.commitScoutLeadProposals()

	// Phase B: Concurrent LeadInvestigators on opened current-sample leads.
	sc.mu.Lock()
	var leadsToInvestigate []artifacts.AuditLead
	for _, lead := range sc.state.AuditLeads {
		if lead.RunID != cfg.RunID || lead.SampleIndex != cfg.SampleIndex {
			continue
		}
		if lead.State != artifacts.LeadStateClosed &&
			!(lead.State == artifacts.LeadStateFormalized && leadBackedByAcceptedContract(lead, sc.state.Contracts)) {
			if !sc.completedLeads[lead.LeadID] {
				leadsToInvestigate = append(leadsToInvestigate, cloneLead(lead))
			}
		}
	}
	sort.SliceStable(leadsToInvestigate, func(i, j int) bool {
		return leadsToInvestigate[i].LeadID < leadsToInvestigate[j].LeadID
	})
	policyErr := sc.policyRefusalErr
	sc.mu.Unlock()

	if policyErr == nil && len(leadsToInvestigate) > 0 {
		obligations := LoadObligations(cfg.KnowledgeRoot)
		knowledge := PriorKnowledge{TWEText: cfg.TWEContext}
		fmt.Fprintf(os.Stdout, "[planner/sharded] starting %d LeadInvestigator shard(s) (workers=%d, model=%s)\n",
			len(leadsToInvestigate), workers, cfg.Model)

		var invWG sync.WaitGroup
		for _, lead := range leadsToInvestigate {
			invWG.Add(1)
			go func(target artifacts.AuditLead) {
				defer invWG.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-shardedCtx.Done():
					sc.recordShardFailure("lead:"+target.LeadID, "cancelled", shardedCtx.Err())
					return
				}
				ok := sc.runLeadInvestigator(shardedCtx, target, topo, obligations, knowledge)
				if ok {
					sc.mu.Lock()
					sc.completedLeads[target.LeadID] = true
					if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
						sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
					}
					sc.mu.Unlock()
				}
			}(lead)
		}
		invWG.Wait()
	}

	// Phase C: Honest completion & coverage accounting (never mask shard errors as valid empty).
	sc.mu.Lock()
	defer sc.mu.Unlock()

	var runErr error
	terminationReason := "sharded_done"
	reconStatus := reconStatusSatisfied

	unresolved := unresolvedSampleLeads(sc.state, cfg.RunID, cfg.SampleIndex)
	switch {
	case sc.policyRefusalErr != nil:
		runErr = fmt.Errorf("sharded planner stopped by upstream policy refusal: %w", sc.policyRefusalErr)
		terminationReason = "policy_refusal"
		reconStatus = reconStatusIncomplete
		sc.coverageGaps = unionStrings(sc.coverageGaps, []string{policyRefusalCoverageGap})
	case len(dossiers) > 0 && scoutsSucceeded == 0 && len(sc.state.Contracts) == 0:
		runErr = fmt.Errorf("all %d boundary scout shard(s) failed: %s", len(dossiers), strings.Join(sc.failedShards, ", "))
		terminationReason = "sharded_error"
		reconStatus = reconStatusIncomplete
	case len(sc.failedShards) > 0:
		terminationReason = "sharded_incomplete"
		reconStatus = reconStatusIncomplete
		if len(unresolved) > 0 {
			sc.coverageGaps = unionStrings(sc.coverageGaps, []string{
				"Sharded planner finished with unresolved audit lead(s): " + strings.Join(unresolved, ", "),
			})
		}
	case cfg.StrictContractExit && len(unresolved) > 0:
		terminationReason = "unresolved_leads_incomplete"
		reconStatus = reconStatusIncomplete
		sc.coverageGaps = unionStrings(sc.coverageGaps, []string{
			"Sharded planner stopped with unresolved audit lead(s): " + strings.Join(unresolved, ", "),
		})
	}

	// Write coverage ledger with honest ReconStatus.
	if err := writeShardedCoverageLedger(cfg, sc.recon, projectMap, len(sc.state.AuditLeads), sc.budget, reconStatus); err != nil {
		fmt.Fprintf(os.Stdout, "[planner/sharded] coverage ledger not written: %v\n", err)
	}

	packs := plannerBoundContractPacks(sc.state.Contracts, cfg)
	summary := fmt.Sprintf("Sharded planner completed %d/%d scout shard(s), investigated %d lead(s), and produced %d bound contract pack(s).",
		scoutsSucceeded, len(dossiers), len(leadsToInvestigate), len(packs))
	if sc.triageSummary != nil {
		summary += fmt.Sprintf(" Bounded stratified triage: %d/%d candidate(s) selected, %d/%d batch(es) succeeded (%d failed, %d unrun).",
			sc.triageSummary.SelectedTotal, sc.triageSummary.CandidateTotal,
			sc.triageSummary.SucceededBatches, sc.triageSummary.BatchTotal,
			sc.triageSummary.FailedBatches, sc.triageSummary.UnrunBatches)
	}
	if terminationReason == "policy_refusal" {
		summary = policyRefusalCoverageGap
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
			TaintQueriesUsed:  sc.budget.TaintQueriesUsed,
			RoundsUsed:        sc.budget.RoundsUsed,
			RoundsBudget:      len(dossiers)*scoutMaxRounds + len(leadsToInvestigate)*investigatorMaxRounds,
			TokensUsed:        sc.budget.TokensUsed,
			WallClockMs:       time.Since(sc.loopStartedAt).Milliseconds(),
			TerminationReason: terminationReason,
		},
		FinalSummary: summary,
		CoverageGaps: sc.coverageGaps,
		Errors:       sc.runErrors,
	}

	bundlePath := runfs.EvidenceBundlePath(cfg.RunDir)
	if err := runfs.WriteJSON(bundlePath, bundle); err != nil && runErr == nil {
		runErr = fmt.Errorf("write evidence bundle: %w", err)
	}

	isComplete := runErr == nil && terminationReason == "sharded_done" && reconStatus == reconStatusSatisfied
	var cached *CheckpointResult
	if isComplete {
		cached = &CheckpointResult{Bundle: bundle, CasePacks: packs}
	}
	if err := sc.saveCheckpointLocked(isComplete, terminationReason, cached); err != nil && runErr == nil {
		runErr = fmt.Errorf("persist final sharded checkpoint: %w", err)
	}

	return RunResult{Bundle: bundle, Err: runErr, CasePacks: packs}
}

func (sc *shardedCoordinator) askShardLLM(
	ctx context.Context,
	client llm.Client,
	model string,
	temp float64,
	roleMaxOut int,
	agentID string,
	roundNum int,
	isScout bool,
	isFinal bool,
	systemPrompt string,
	userPrompt string,
) (llm.GenerateResponse, int, int, error) {
	inputEst := estimateRequestInputTokens(systemPrompt, userPrompt)
	minOut := minimumRequestOutput(RunConfig{Model: model, ReasoningEffort: sc.cfg.ReasoningEffort, MaxOutputTokens: roleMaxOut})
	outBudget, reserved, ok := sc.reserveShardTokens(inputEst, isScout, isFinal, roleMaxOut, minOut)
	if !ok {
		return llm.GenerateResponse{}, 0, 0, fmt.Errorf("%w: need %d output tokens, have %d", errReplyBudget, minOut, outBudget)
	}
	actualTokens := 0
	defer func() {
		sc.settleShardTokens(reserved, actualTokens, isScout)
		sc.mu.Lock()
		if err := sc.saveBudgetCheckpointLocked(); err != nil {
			sc.recordShardFailureLocked("checkpoint", "budget_checkpoint_error", err)
		}
		sc.mu.Unlock()
	}()
	sc.mu.Lock()
	checkpointErr := sc.saveBudgetCheckpointLocked()
	sc.mu.Unlock()
	if checkpointErr != nil {
		return llm.GenerateResponse{}, 0, 0, fmt.Errorf("persist LLM budget reservation: %w", checkpointErr)
	}
	reqCtx := ctx
	if deadline, ok := sc.wallClockDeadline(); ok {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	_ = sc.cfg.Events.Emit(events.LLMCallStarted(sc.cfg.RunID, agentID, model, roundNum))
	resp, err := client.Generate(reqCtx, llm.GenerateRequest{
		SystemPrompt:    systemPrompt,
		Messages:        []llm.Message{{Role: "user", Content: userPrompt}},
		Temperature:     temp,
		JSONMode:        true,
		MaxOutputTokens: outBudget,
	})
	if err != nil {
		var inTok, outTok int
		if resp.Usage.PromptTokens > 0 || resp.Usage.CompletionTokens > 0 || resp.Usage.TotalTokens > 0 {
			inTok, outTok = accountedUsage(resp, inputEst)
			actualTokens = inTok + outTok
		}
		failed := events.LLMCallCompleted(sc.cfg.RunID, agentID, model, roundNum, inTok, outTok, "", "").
			WithWireBodies(
				events.BestEffortRef(sc.cfg.Blobs, []byte(resp.RawRequest)),
				events.BestEffortRef(sc.cfg.Blobs, []byte(resp.Raw)))
		failed.Error = err.Error()
		_ = sc.cfg.Events.Emit(failed)
		return llm.GenerateResponse{}, inTok, outTok, err
	}
	inTok, outTok := accountedUsage(resp, inputEst)
	actualTokens = inTok + outTok
	var promptBlob, responseBlob string
	if sc.cfg.Blobs != nil {
		if ref, berr := sc.cfg.Blobs.WriteString(systemPrompt + "\n\n---\n\n" + userPrompt); berr == nil {
			promptBlob = ref
		}
		if ref, berr := sc.cfg.Blobs.WriteString(resp.Text); berr == nil {
			responseBlob = ref
		}
	}
	_ = sc.cfg.Events.Emit(events.LLMCallCompleted(
		sc.cfg.RunID, agentID, model, roundNum, inTok, outTok, promptBlob, responseBlob).
		WithWireBodies(
			events.BestEffortRef(sc.cfg.Blobs, []byte(resp.RawRequest)),
			events.BestEffortRef(sc.cfg.Blobs, []byte(resp.Raw))))
	return resp, inTok, outTok, nil
}

func (sc *shardedCoordinator) runBoundaryScout(ctx context.Context, dossier scoutDossier, includePrescan bool) bool {
	agentID := "scout-" + dossier.Bucket
	scoutReg := sc.cfg.Registry.Without(passBOnlyActions...)
	systemPrompt := BuildSystemPrompt(advertisedActions(scoutReg), "", PriorKnowledge{}, PhaseReconnaissance)
	dossierBlock := formatScoutDossier(dossier, sc.cfg.PreScannedTaint, includePrescan)

	var localHistory []artifacts.RoundRecord
	loopDet := NewLoopDetector()
	fileReadCount := map[string]int{}
	assignedPaths := map[string]bool{}
	for _, closure := range dossier.Closures {
		assignedPaths[filepath.ToSlash(filepath.Clean(closure.RootPath))] = true
		for _, member := range closure.Members {
			assignedPaths[filepath.ToSlash(filepath.Clean(member.Path))] = true
		}
	}
	readAssignedSource := len(dossier.Closures) == 0

	for step := 1; step <= scoutMaxRounds; step++ {
		if sc.wallClockExhausted() {
			sc.recordShardFailure("scout:"+dossier.Bucket, "wall_clock", context.DeadlineExceeded)
			return false
		}
		roundNum := sc.allocRound(true)
		if roundNum == 0 {
			sc.recordShardFailure("scout:"+dossier.Bucket, "round_budget_exhausted", nil)
			return false
		}
		_ = sc.cfg.Events.Emit(events.PlannerRoundStarted(sc.cfg.RunID, agentID, roundNum))

		isFinal := step == scoutMaxRounds
		var prompt strings.Builder
		if step == 1 {
			prompt.WriteString(dossierBlock)
		}
		fmt.Fprintf(&prompt, "=== SCOUT ROUND %d/%d (bucket=%s) ===\n", step, scoutMaxRounds, dossier.Bucket)
		if len(localHistory) > 0 {
			prompt.WriteString("=== RECENT OBSERVATIONS ===\n")
			start := len(localHistory) - 2
			if start < 0 {
				start = 0
			}
			for _, r := range localHistory[start:] {
				for _, o := range r.Observations {
					if o.OK {
						fmt.Fprintf(&prompt, "  [%s] OK  ref=%s\n", o.Name, o.Ref)
					} else {
						fmt.Fprintf(&prompt, "  [%s] ERROR: %s  ref=%s\n", o.Name, o.Error, o.Ref)
					}
					if o.Output != "" {
						body := o.Output
						if len(body) > 2400 {
							body = body[:2400] + "\n... (truncated)"
						}
						fmt.Fprintf(&prompt, "    %s\n", strings.ReplaceAll(body, "\n", "\n    "))
					}
				}
			}
		}
		if isFinal {
			prompt.WriteString("\nFINAL SCOUT ROUND: open any grounded lead you found (`open_audit_lead`) and/or call `done` with a brief summary.\n")
		} else {
			prompt.WriteString("\nPick up to 3 actions (`read_file` on distinct assigned closures, `get_struct_flows`, `open_audit_lead`, or `done`). Reply with strict JSON only.\n")
		}

		resp, inTok, outTok, err := sc.askShardLLM(ctx, sc.cfg.ScoutClient, sc.cfg.ScoutModel, sc.cfg.ScoutTemperature, sc.cfg.ScoutMaxOutputTokens, agentID, roundNum, true, isFinal, systemPrompt, prompt.String())
		if err != nil {
			reason := "llm_error"
			if errors.Is(err, errReplyBudget) {
				reason = "token_budget_insufficient"
			} else if llm.IsPolicyRefusal(err) {
				reason = "policy_refusal"
			} else if errors.Is(err, context.DeadlineExceeded) {
				reason = "wall_clock"
			}
			sc.recordShardFailure("scout:"+dossier.Bucket, reason, err)
			_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
			return false
		}
		parsed, parseErr := ParseLLMResponse(resp.Text)
		if parseErr != nil {
			sc.recordShardFailure("scout:"+dossier.Bucket, "llm_malformed", parseErr)
			_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
			return false
		}

		roundRec := artifacts.RoundRecord{Round: roundNum, Thought: parsed.Thought, TokensIn: inTok, TokensOut: outTok}
		sc.mu.Lock()
		if sc.mutatingRounds == nil {
			sc.mutatingRounds = map[int]bool{}
		}
		sc.mutatingRounds[roundNum] = true
		sc.mu.Unlock()
		limit := len(parsed.Actions)
		if limit > sc.cfg.MaxActionsPerRound {
			limit = sc.cfg.MaxActionsPerRound
		}
		finished := false
		for i := 0; i < limit; i++ {
			act := parsed.Actions[i]
			roundRec.Actions = append(roundRec.Actions, artifacts.RoundAction{Name: act.Name, Args: act.Args})
			if loopDet.ShouldReject(act.Name, string(act.Args)) {
				roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
					Name: act.Name, OK: false, ActionIndex: i, Error: "loop detector: repeated action",
				})
				continue
			}
			loopDet.Record(act.Name, string(act.Args))

			var res actions.ActionResult
			switch act.Name {
			case ActionOpenAuditLead:
				sc.mu.Lock()
				canonArgs := canonicalizeScoutLeadArgs(act.Args, sc.recon, sc.symbolCatalog)
				payload, perr := parseOpenAuditLead(canonArgs)
				if perr != nil {
					res = actions.ActionResult{Name: ActionOpenAuditLead, OK: false, Error: "open_audit_lead: could not read the args: " + perr.Error()}
				} else {
					// Validate payload against current recon & observations without racing on maxShardedLeads;
					// deterministic dedup, sort, truncation, and openLead persistence run once Phase A finishes.
					probeRecon := snapshotRecon(sc.recon).restore()
					var validated artifacts.AuditLead
					validated, res = tryOpenAuditLeadWithPrescan(probeRecon, sc.observations, payload, false)
					if res.OK {
						payload.ReasonFactRefs = validated.ReasonFactRefs
						reencoded, _ := json.Marshal(payload)
						var primaryID artifacts.SymbolID
						var primaryPath, primarySym string
						if len(validated.TargetSymbolIDs) > 0 {
							primaryID = validated.TargetSymbolIDs[0]
							primaryPath = symbolIDPath(primaryID)
							primarySym = symbolIDName(primaryID)
						}
						sc.scoutProposals = append(sc.scoutProposals, scoutLeadProposal{
							Bucket:        dossier.Bucket,
							PrimaryPath:   primaryPath,
							PrimarySymbol: primarySym,
							PrimaryID:     primaryID,
							Question:      strings.TrimSpace(validated.SecurityQuestion),
							CanonArgs:     reencoded,
							RoundNum:      roundNum,
						})
					}
				}
				sc.mu.Unlock()
			case "done":
				if !readAssignedSource {
					res = actions.ActionResult{Name: "done", OK: false, Error: "done refused: read source from an assigned boundary closure before completing this scout"}
				} else {
					res = scoutReg.Run(ctx, actions.ActionRequest{Name: "done", Args: act.Args, RepoRoot: sc.cfg.RepoRoot, RunDir: sc.cfg.RunDir})
				}
				if res.OK {
					finished = true
				}
			default:
				if act.Name == "read_file" {
					var rfArgs struct {
						Path string `json:"path"`
					}
					if json.Unmarshal(act.Args, &rfArgs) == nil && rfArgs.Path != "" {
						if fileReadCount[rfArgs.Path] >= 2 {
							res = actions.ActionResult{
								Name:  "read_file",
								OK:    false,
								Error: "scout breadth limit: already read " + rfArgs.Path + " twice in this scout shard — inspect another assigned closure file or call open_audit_lead",
							}
							break
						}
						fileReadCount[rfArgs.Path]++
					}
				}
				req := actions.ActionRequest{
					Name: act.Name, Args: act.Args, RepoRoot: sc.cfg.RepoRoot, RunDir: sc.cfg.RunDir,
					Repository: sc.cfg.Profile.RepoURL, Commit: sc.cfg.Profile.Commit,
					Executor: sc.cfg.Executor, RunID: sc.cfg.RunID, Agent: agentID, Round: roundNum,
				}
				if act.Name == actions.TraceTaintAction {
					timeout := sc.budget.TaintQueryTimeout
					if timeout <= 0 {
						timeout = 5 * time.Minute
					}
					req.TracePolicy = &actions.TracePolicy{
						ObservedSymbol: func(id artifacts.SymbolID) bool {
							sc.mu.Lock()
							defer sc.mu.Unlock()
							return sc.recon.SawSymbol(id)
						},
						TakeQuery: sc.consumeTaintQuery,
						Timeout:   timeout,
					}
				}
				actionCtx, cancelAction := sc.shardActionContext(ctx, act.Name)
				res = scoutReg.Run(actionCtx, req)
				cancelAction()
			}
			if act.Name == "read_file" && res.OK && strings.TrimSpace(res.Output) != "" {
				var read struct {
					Path string `json:"path"`
				}
				if json.Unmarshal(act.Args, &read) == nil && assignedPaths[filepath.ToSlash(filepath.Clean(read.Path))] {
					readAssignedSource = true
				}
			}

			outBlob := events.BestEffortRef(sc.cfg.Blobs, []byte(res.Output))
			if !scoutReg.IsExecutorBacked(act.Name) {
				_ = sc.cfg.Events.Emit(events.ToolCallCompleted(sc.cfg.RunID, agentID, res.Name, roundNum, res.OK, res.DurationMs, outBlob, res.Error))
			}
			body, cutHere := excerpt(res.Output, outBlob)
			ref := MakeObservationRef(sc.cfg.RunID, sc.cfg.SampleIndex, roundNum, i, outBlob)

			sc.mu.Lock()
			if act.Name != "read_file" && act.Name != "tree_sitter_outline" {
				sc.recon.ObserveAction(act.Name, act.Args, res.OK)
			}
			sc.recon.ObserveSourceOutput(act.Name, act.Args, body, res.OK)
			sc.observations.Record(ref, res.OK)
			if res.OK {
				trackObservedPaths(act.Name, act.Args, res.Output, sc.cfg.RepoRoot, sc.observedPaths)
				if act.Name == "fact_layer_query" || act.Name == actions.TraceTaintAction {
					if tf := toolFactRefFrom(res.Output); tf != "" {
						sc.executedToolFactRefs = unionStrings(sc.executedToolFactRefs, []string{tf})
					}
				}
			}
			sc.mu.Unlock()

			_ = sc.cfg.Events.Emit(events.PlannerObservationRecorded(
				sc.cfg.RunID, agentID, res.Name, roundNum, sc.cfg.SampleIndex, res.OK, ref, outBlob))

			roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
				Name: res.Name, OK: res.OK, Ref: ref, OutputBlob: outBlob, ActionIndex: i,
				Phase: PhaseReconnaissance, Output: body, Error: res.Error,
				Truncated: res.Truncated || cutHere, DurationMs: res.DurationMs,
			})
			if finished {
				break
			}
		}

		sc.mu.Lock()
		persistErr := sc.state.AppendRoundAndPersist(roundRec, sc.roundsLog)
		if persistErr == nil {
			delete(sc.mutatingRounds, roundNum)
		}
		sc.mu.Unlock()
		_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, len(roundRec.Actions), len(roundRec.Observations)))
		if persistErr != nil {
			sc.recordShardFailure("scout:"+dossier.Bucket, "persist_error", persistErr)
			return false
		}
		localHistory = append(localHistory, roundRec)
		if finished {
			break
		}
	}
	if !readAssignedSource {
		sc.recordShardFailure("scout:"+dossier.Bucket, "assigned_source_unread", nil)
		return false
	}
	return true
}

func (sc *shardedCoordinator) runLeadInvestigator(
	ctx context.Context,
	lead artifacts.AuditLead,
	topo artifacts.BoundaryTopology,
	obligations string,
	knowledge PriorKnowledge,
) bool {
	agentID := "investigator-" + lead.LeadID
	systemPrompt := BuildSystemPrompt(advertisedActions(sc.cfg.Registry), obligations, knowledge, PhaseInvestigation)
	closureContext := formatLeadClosureContext(lead, topo)

	var localHistory []artifacts.RoundRecord
	loopDet := NewLoopDetector()

	for step := 1; step <= investigatorMaxRounds; step++ {
		if sc.wallClockExhausted() {
			sc.recordShardFailure("lead:"+lead.LeadID, "wall_clock", context.DeadlineExceeded)
			return false
		}
		roundNum := sc.allocRound(false)
		if roundNum == 0 {
			sc.recordShardFailure("lead:"+lead.LeadID, "round_budget_exhausted", nil)
			return false
		}
		_ = sc.cfg.Events.Emit(events.PlannerRoundStarted(sc.cfg.RunID, agentID, roundNum))

		isFinal := step == investigatorMaxRounds
		inFreeze := sc.cfg.StrictContractExit && step >= investigatorMaxRounds-1

		var prompt strings.Builder
		fmt.Fprintf(&prompt, "=== ISOLATED LEAD INVESTIGATION (%s, round %d/%d) ===\n", lead.LeadID, step, investigatorMaxRounds)
		fmt.Fprintf(&prompt, "security_question: %s\n", lead.SecurityQuestion)
		fmt.Fprintf(&prompt, "target_symbol_ids: %v\n", lead.TargetSymbolIDs)
		fmt.Fprintf(&prompt, "reason_fact_refs: %v\n", lead.ReasonFactRefs)
		if step == 1 && closureContext != "" {
			prompt.WriteString("\n" + closureContext + "\n")
		}
		if step == 1 && sc.cfg.PreScannedTaint != nil {
			prompt.WriteString(preScannedTaintBlock(sc.cfg.PreScannedTaint))
		}
		if len(localHistory) > 0 {
			prompt.WriteString("\n=== RECENT OBSERVATIONS ===\n")
			start := len(localHistory) - 2
			if start < 0 {
				start = 0
			}
			for _, r := range localHistory[start:] {
				for _, o := range r.Observations {
					if o.OK {
						fmt.Fprintf(&prompt, "  [%s] OK  ref=%s\n", o.Name, o.Ref)
					} else {
						fmt.Fprintf(&prompt, "  [%s] ERROR: %s  ref=%s\n", o.Name, o.Error, o.Ref)
					}
					if o.Output != "" {
						body := o.Output
						if len(body) > 2600 {
							body = body[:2600] + "\n... (truncated)"
						}
						fmt.Fprintf(&prompt, "    %s\n", strings.ReplaceAll(body, "\n", "\n    "))
					}
				}
			}
		}
		switch {
		case isFinal:
			prompt.WriteString("\nFINAL ROUND FOR THIS LEAD: You MUST resolve `" + lead.LeadID + "` now via `formalize_contract` (if a concrete security obligation holds/fails) or `close_lead` (if ruled out), followed by `done`.\n")
		case inFreeze:
			prompt.WriteString("\nCONVERGENCE FREEZE: Exploration and `read_file` are disabled. Call `formalize_contract` or `close_lead` for `" + lead.LeadID + "`, then `done`.\n")
		default:
			prompt.WriteString("\nVerify or falsify `" + lead.LeadID + "`. Read caller/callee bodies, check struct flows, then call `formalize_contract` or `close_lead` and `done`. Reply with strict JSON only.\n")
		}

		resp, inTok, outTok, err := sc.askShardLLM(ctx, sc.cfg.Client, sc.cfg.Model, sc.cfg.Temperature, sc.cfg.MaxOutputTokens, agentID, roundNum, false, isFinal, systemPrompt, prompt.String())
		if err != nil {
			reason := "llm_error"
			if errors.Is(err, errReplyBudget) {
				reason = "token_budget_insufficient"
			} else if llm.IsPolicyRefusal(err) {
				reason = "policy_refusal"
			} else if errors.Is(err, context.DeadlineExceeded) {
				reason = "wall_clock"
			}
			sc.recordShardFailure("lead:"+lead.LeadID, reason, err)
			_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
			return false
		}
		parsed, parseErr := ParseLLMResponse(resp.Text)
		if parseErr != nil {
			sc.recordShardFailure("lead:"+lead.LeadID, "llm_malformed", parseErr)
			_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
			return false
		}

		roundRec := artifacts.RoundRecord{Round: roundNum, Thought: parsed.Thought, TokensIn: inTok, TokensOut: outTok}
		sc.mu.Lock()
		if sc.mutatingRounds == nil {
			sc.mutatingRounds = map[int]bool{}
		}
		sc.mutatingRounds[roundNum] = true
		sc.mu.Unlock()
		limit := len(parsed.Actions)
		if limit > sc.cfg.MaxActionsPerRound {
			limit = sc.cfg.MaxActionsPerRound
		}
		finished := false
		for i := 0; i < limit; i++ {
			act := parsed.Actions[i]
			roundRec.Actions = append(roundRec.Actions, artifacts.RoundAction{Name: act.Name, Args: act.Args})
			if loopDet.ShouldReject(act.Name, string(act.Args)) {
				roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
					Name: act.Name, OK: false, ActionIndex: i, Error: "loop detector: repeated action",
				})
				continue
			}
			loopDet.Record(act.Name, string(act.Args))

			var res actions.ActionResult
			switch {
			case inFreeze && !allowedInConvergenceFreeze(act.Name):
				res = actions.ActionResult{Name: act.Name, OK: false, Error: "convergence freeze: call formalize_contract or close_lead for " + lead.LeadID + " and done"}
			case act.Name == ActionUpdateLead:
				sc.mu.Lock()
				res = updateLead(sc.cfg, sc.state, sc.observations, sc.executedToolFactRefs, act.Args, roundNum)
				sc.mu.Unlock()
			case act.Name == ActionFormalizeContract:
				sc.mu.Lock()
				res = formalizeContract(sc.cfg, sc.state, sc.observations, sc.executedToolFactRefs, roundRec, act.Args)
				sc.mu.Unlock()
			case act.Name == ActionCloseLead:
				sc.mu.Lock()
				res = closeLead(sc.cfg, sc.state, sc.observations, sc.executedToolFactRefs, act.Args, roundNum)
				sc.mu.Unlock()
			case act.Name == "done":
				var payload actions.DonePayload
				if uerr := json.Unmarshal(act.Args, &payload); uerr != nil {
					res = actions.ActionResult{Name: "done", OK: false, Error: "invalid done args: " + uerr.Error()}
				} else {
					sc.mu.Lock()
					if len(payload.CaseInvariants) > 0 {
						drafts := filterOutAcceptedDrafts(payload.CaseInvariants, sc.state.Contracts)
						_, bindErrs := bindPlannerContractsWithState(drafts, sc.cfg, sc.state, &sc.observations, sc.executedToolFactRefs, &roundRec)
						sc.runErrors = append(sc.runErrors, bindErrs...)
					}
					leadResolved := isLeadResolvedLocked(sc.state, sc.cfg.RunID, sc.cfg.SampleIndex, lead.LeadID)
					sc.mu.Unlock()
					if sc.cfg.StrictContractExit && !isFinal && !leadResolved {
						res = actions.ActionResult{
							Name:  "done",
							OK:    false,
							Error: "done refused: lead " + lead.LeadID + " is still open; call formalize_contract or close_lead first",
						}
					} else {
						res = actions.ActionResult{Name: "done", OK: true, Output: string(act.Args)}
						finished = true
					}
				}
			default:
				req := actions.ActionRequest{
					Name: act.Name, Args: act.Args, RepoRoot: sc.cfg.RepoRoot, RunDir: sc.cfg.RunDir,
					Repository: sc.cfg.Profile.RepoURL, Commit: sc.cfg.Profile.Commit,
					Executor: sc.cfg.Executor, RunID: sc.cfg.RunID, Agent: agentID, Round: roundNum,
				}
				if act.Name == actions.TraceTaintAction {
					timeout := sc.budget.TaintQueryTimeout
					if timeout <= 0 {
						timeout = 5 * time.Minute
					}
					req.TracePolicy = &actions.TracePolicy{
						ObservedSymbol: func(id artifacts.SymbolID) bool {
							sc.mu.Lock()
							defer sc.mu.Unlock()
							return sc.recon.SawSymbol(id)
						},
						TakeQuery: sc.consumeTaintQuery,
						Timeout:   timeout,
					}
				}
				actionCtx, cancelAction := sc.shardActionContext(ctx, act.Name)
				res = sc.cfg.Registry.Run(actionCtx, req)
				cancelAction()
			}

			outBlob := events.BestEffortRef(sc.cfg.Blobs, []byte(res.Output))
			if !sc.cfg.Registry.IsExecutorBacked(act.Name) {
				_ = sc.cfg.Events.Emit(events.ToolCallCompleted(sc.cfg.RunID, agentID, res.Name, roundNum, res.OK, res.DurationMs, outBlob, res.Error))
			}
			body, cutHere := excerpt(res.Output, outBlob)
			ref := MakeObservationRef(sc.cfg.RunID, sc.cfg.SampleIndex, roundNum, i, outBlob)

			sc.mu.Lock()
			if act.Name != "read_file" && act.Name != "tree_sitter_outline" {
				sc.recon.ObserveAction(act.Name, act.Args, res.OK)
			}
			sc.recon.ObserveSourceOutput(act.Name, act.Args, body, res.OK)
			sc.observations.Record(ref, res.OK)
			if res.OK {
				trackObservedPaths(act.Name, act.Args, res.Output, sc.cfg.RepoRoot, sc.observedPaths)
				if act.Name == "fact_layer_query" || act.Name == actions.TraceTaintAction {
					if tf := toolFactRefFrom(res.Output); tf != "" {
						sc.executedToolFactRefs = unionStrings(sc.executedToolFactRefs, []string{tf})
					}
				}
			}
			sc.mu.Unlock()

			_ = sc.cfg.Events.Emit(events.PlannerObservationRecorded(
				sc.cfg.RunID, agentID, res.Name, roundNum, sc.cfg.SampleIndex, res.OK, ref, outBlob))

			roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
				Name: res.Name, OK: res.OK, Ref: ref, OutputBlob: outBlob, ActionIndex: i,
				Phase: PhaseInvestigation, Output: body, Error: res.Error,
				Truncated: res.Truncated || cutHere, DurationMs: res.DurationMs,
			})
			if finished {
				break
			}
		}

		sc.mu.Lock()
		persistErr := sc.state.AppendRoundAndPersist(roundRec, sc.roundsLog)
		if persistErr == nil {
			delete(sc.mutatingRounds, roundNum)
		}
		resolvedNow := isLeadResolvedLocked(sc.state, sc.cfg.RunID, sc.cfg.SampleIndex, lead.LeadID)
		sc.mu.Unlock()
		_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, len(roundRec.Actions), len(roundRec.Observations)))
		if persistErr != nil {
			sc.recordShardFailure("lead:"+lead.LeadID, "persist_error", persistErr)
			return false
		}
		localHistory = append(localHistory, roundRec)
		if finished || (resolvedNow && step >= investigatorMaxRounds) {
			break
		}
	}
	sc.mu.Lock()
	resolved := isLeadResolvedLocked(sc.state, sc.cfg.RunID, sc.cfg.SampleIndex, lead.LeadID)
	sc.mu.Unlock()
	return resolved
}

func isLeadResolvedLocked(state *PlannerState, runID string, sampleIndex int, leadID string) bool {
	for _, l := range state.AuditLeads {
		if l.RunID == runID && l.SampleIndex == sampleIndex && l.LeadID == leadID {
			if l.State == artifacts.LeadStateClosed {
				return true
			}
			if l.State == artifacts.LeadStateFormalized && leadBackedByAcceptedContract(l, state.Contracts) {
				return true
			}
			return false
		}
	}
	return false
}

func (sc *shardedCoordinator) shardActionContext(ctx context.Context, name string) (context.Context, context.CancelFunc) {
	if deadline, ok := sc.wallClockDeadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		if name == actions.TraceTaintAction || sc.cfg.Budget.PerActionTimeout <= 0 {
			return ctx, cancel
		}
		actionCtx, cancelAction := context.WithTimeout(ctx, sc.cfg.Budget.PerActionTimeout)
		return actionCtx, func() { cancelAction(); cancel() }
	}
	if name != actions.TraceTaintAction && sc.cfg.Budget.PerActionTimeout > 0 {
		return context.WithTimeout(ctx, sc.cfg.Budget.PerActionTimeout)
	}
	return context.WithCancel(ctx)
}

func formatLeadClosureContext(lead artifacts.AuditLead, topo artifacts.BoundaryTopology) string {
	targetSet := map[artifacts.SymbolID]bool{}
	for _, id := range lead.TargetSymbolIDs {
		targetSet[id] = true
	}
	var b strings.Builder
	for _, c := range topo.EntryClosures {
		matched := targetSet[c.RootSymbolID]
		if !matched {
			for _, m := range c.Members {
				if targetSet[m.SymbolID] {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		fmt.Fprintf(&b, "Matched boundary closure: %s (%s:%d) buckets=%v\n", c.RootName, c.RootPath, c.RootStartLine, c.Buckets)
		for _, m := range c.Members {
			fmt.Fprintf(&b, "  - hop=%d %s (%s:%d) writes=%v\n", m.Hop, m.Name, m.Path, m.Line, m.DirectFieldWrites)
		}
		break
	}
	return b.String()
}

func writeShardedCoverageLedger(cfg RunConfig, recon *ReconState, m artifacts.ProjectMap, leadsOpened int, budget Budget, reconStatus string) error {
	if cfg.RunDir == "" {
		return nil
	}
	path := runfs.CoverageLedgerPath(cfg.RunDir)
	var ledger artifacts.CoverageLedger
	_ = runfs.ReadJSON(path, &ledger)

	ledger.SchemaVersion = "teecheck.coverage_ledger.v1"
	ledger.RunID = cfg.RunID
	ledger.ModulesTotal = len(m.Modules)
	ledger.FunctionCapsulesTotal = totalFunctions(m)

	entry := artifacts.SampleCoverage{
		SampleIndex:        cfg.SampleIndex,
		ReconMode:          string(recon.Mode),
		ReconStatus:        reconStatus,
		ModulesReviewed:    recon.ModulesReviewed(),
		CapsulesReviewed:   recon.DistinctSymbolsViewed(),
		FilesRead:          recon.DistinctFilesRead(),
		RelationQueriesRun: recon.RelationQueries(),
		RoundsUsed:         budget.RoundsUsed,
		ReconRoundsUsed:    budget.ReconRoundsUsed,
		LeadsOpened:        leadsOpened,
	}
	entryCoverage := recon.EntryCoverage()
	entry.EntrySurfaces = &artifacts.EntrySurfaceCoverage{
		Capability: entryCoverage.Capability, Total: entryCoverage.Total,
		Required: entryCoverage.Required, Read: entryCoverage.Read,
		ModulesTotal: entryCoverage.ModulesTotal, ModulesRequired: entryCoverage.ModulesRequired, ModulesRead: entryCoverage.ModulesRead,
		ReadSymbolIDs: entryCoverage.ReadSymbolIDs, GateApplies: false,
		Complete: reconStatus == reconStatusSatisfied,
	}
	if current, err := contractLeads(cfg); err == nil {
		for _, lead := range current {
			if lead.State == artifacts.LeadStateClosed {
				entry.LeadsClosed++
			}
		}
	}
	replaced := false
	for i := range ledger.BySample {
		if ledger.BySample[i].SampleIndex == entry.SampleIndex {
			ledger.BySample[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		ledger.BySample = append(ledger.BySample, entry)
	}
	sort.Slice(ledger.BySample, func(i, j int) bool {
		return ledger.BySample[i].SampleIndex < ledger.BySample[j].SampleIndex
	})

	reviewed := map[string]bool{}
	capsules, leads := 0, 0
	for _, s := range ledger.BySample {
		for _, mod := range s.ModulesReviewed {
			reviewed[mod] = true
		}
		capsules += s.CapsulesReviewed
		leads += max(0, s.LeadsOpened-s.LeadsClosed)
	}
	ledger.ModulesReviewed = len(reviewed)
	ledger.FunctionCapsulesReviewed = capsules
	ledger.LeadsOpen = leads
	ledger.UnreviewedClusters = []string{}
	for _, mod := range m.Modules {
		if !reviewed[mod.Path] {
			ledger.UnreviewedClusters = append(ledger.UnreviewedClusters, mod.Path)
		}
	}
	sort.Strings(ledger.UnreviewedClusters)
	return runfs.WriteJSON(path, ledger)
}

func buildScoutSymbolCatalog(runDir string, topo artifacts.BoundaryTopology) []artifacts.SymbolID {
	seen := map[artifacts.SymbolID]bool{}
	var out []artifacts.SymbolID
	add := func(id artifacts.SymbolID) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	if runDir != "" {
		var facts artifacts.RepoFacts
		if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err == nil {
			for _, sym := range facts.Symbols {
				add(sym.SymbolID)
			}
		}
	}
	for _, c := range topo.EntryClosures {
		add(c.RootSymbolID)
		for _, m := range c.Members {
			add(m.SymbolID)
		}
	}
	for _, br := range topo.StructFieldBridges {
		for _, id := range br.DirectWriters {
			add(id)
		}
		for _, id := range br.NonWriteAccessors {
			add(id)
		}
	}
	return out
}

func symbolIDName(id artifacts.SymbolID) string {
	s := string(id)
	if strings.Contains(s, "::") {
		parts := strings.SplitN(s, "::", 2)
		name := parts[1]
		if idx := strings.IndexByte(name, '('); idx >= 0 {
			name = name[:idx]
		}
		return strings.TrimSpace(name)
	}
	parts := strings.SplitN(s, ":", 4)
	if len(parts) == 4 {
		name := parts[3]
		if idx := strings.IndexByte(name, '('); idx >= 0 {
			name = name[:idx]
		}
		return strings.TrimSpace(name)
	}
	if idx := strings.IndexByte(s, '('); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func parseRawTargetPathAndName(raw artifacts.SymbolID) (string, string) {
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "src/")
	if strings.Contains(s, "::") {
		parts := strings.SplitN(s, "::", 2)
		path := strings.TrimPrefix(strings.TrimSpace(parts[0]), "src/")
		name := symbolIDName(artifacts.SymbolID(parts[1]))
		return path, name
	}
	parts := strings.SplitN(s, ":", 4)
	if len(parts) == 4 {
		path := strings.TrimPrefix(strings.TrimSpace(parts[1]), "src/")
		return path, symbolIDName(raw)
	}
	return "", symbolIDName(raw)
}

// canonicalizeScoutLeadArgs resolves informal scout target_symbol_ids (such as
// "path::func" or a slightly misremembered file prefix for a function the scout
// actually read via read_file) against canonical index/topology symbols whose
// definitions were genuinely observed in recon. Secondary unseen callers are
// moved into requested_context for LeadInvestigator when at least one primary
// target is grounded in observed source.
func canonicalizeScoutLeadArgs(args json.RawMessage, recon *ReconState, catalog []artifacts.SymbolID) json.RawMessage {
	if recon == nil || len(catalog) == 0 {
		return args
	}
	payload, err := parseOpenAuditLead(args)
	if err != nil || len(payload.TargetSymbolIDs) == 0 {
		return args
	}
	var grounded []artifacts.SymbolID
	seenGrounded := map[artifacts.SymbolID]bool{}
	var deferred []string
	changed := false

	addGrounded := func(id artifacts.SymbolID) {
		if !seenGrounded[id] {
			seenGrounded[id] = true
			grounded = append(grounded, id)
		}
	}

	for _, raw := range payload.TargetSymbolIDs {
		if recon.SawSymbol(raw) {
			addGrounded(raw)
			continue
		}
		rawPath, rawName := parseRawTargetPathAndName(raw)
		if rawName == "" {
			deferred = append(deferred, "Inspect related target: "+string(raw))
			continue
		}
		var exactMatch artifacts.SymbolID
		var nameMatches []artifacts.SymbolID
		for _, cand := range catalog {
			if !recon.SawSymbol(cand) {
				continue
			}
			if symbolIDName(cand) != rawName {
				continue
			}
			candPath := symbolIDPath(cand)
			if rawPath != "" && (candPath == rawPath || strings.HasSuffix(candPath, "/"+rawPath)) {
				exactMatch = cand
				break
			}
			nameMatches = append(nameMatches, cand)
		}
		if exactMatch != "" {
			addGrounded(exactMatch)
			changed = true
		} else if len(nameMatches) == 1 {
			addGrounded(nameMatches[0])
			changed = true
		} else {
			deferred = append(deferred, "Inspect related symbol: "+string(raw))
		}
	}

	if len(grounded) == 0 || (!changed && len(deferred) == 0) {
		return args
	}
	payload.TargetSymbolIDs = grounded
	if len(deferred) > 0 {
		payload.RequestedContext = unionStrings(payload.RequestedContext, deferred)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return args
	}
	return b
}

func cloneTriageBatches(in map[int]TriageBatchRecord) map[int]TriageBatchRecord {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int]TriageBatchRecord, len(in))
	for k, v := range in {
		cp := v
		cp.Candidates = append([]TriageGroundedCandidate(nil), v.Candidates...)
		out[k] = cp
	}
	return out
}

// commitScoutLeadProposals deterministically sorts, deduplicates, truncates to
// maxShardedLeads, and persists all validated BoundaryScout lead proposals
// through the unified openLead path once Phase A workers have finished.
func (sc *shardedCoordinator) commitScoutLeadProposals() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.scoutProposals) == 0 {
		return
	}
	sort.SliceStable(sc.scoutProposals, func(i, j int) bool {
		if sc.scoutProposals[i].Bucket != sc.scoutProposals[j].Bucket {
			return sc.scoutProposals[i].Bucket < sc.scoutProposals[j].Bucket
		}
		if sc.scoutProposals[i].PrimaryPath != sc.scoutProposals[j].PrimaryPath {
			return sc.scoutProposals[i].PrimaryPath < sc.scoutProposals[j].PrimaryPath
		}
		if sc.scoutProposals[i].PrimarySymbol != sc.scoutProposals[j].PrimarySymbol {
			return sc.scoutProposals[i].PrimarySymbol < sc.scoutProposals[j].PrimarySymbol
		}
		if sc.scoutProposals[i].PrimaryID != sc.scoutProposals[j].PrimaryID {
			return sc.scoutProposals[i].PrimaryID < sc.scoutProposals[j].PrimaryID
		}
		return sc.scoutProposals[i].Question < sc.scoutProposals[j].Question
	})
	seenTarget := map[artifacts.SymbolID]bool{}
	for _, existing := range sc.state.AuditLeads {
		if existing.RunID == sc.cfg.RunID && existing.SampleIndex == sc.cfg.SampleIndex {
			for _, id := range existing.TargetSymbolIDs {
				seenTarget[id] = true
			}
		}
	}
	for _, prop := range sc.scoutProposals {
		if len(sc.state.AuditLeads) >= maxShardedLeads {
			break
		}
		if prop.PrimaryID != "" && seenTarget[prop.PrimaryID] {
			continue
		}
		lead, res := openLead(sc.cfg, sc.recon, sc.observations, prop.CanonArgs, prop.RoundNum, sc.state)
		if !res.OK {
			continue
		}
		sc.state.AuditLeads = append(sc.state.AuditLeads, lead)
		if prop.PrimaryID != "" {
			seenTarget[prop.PrimaryID] = true
		}
	}
	sc.scoutProposals = nil
	if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
		sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
	}
}
