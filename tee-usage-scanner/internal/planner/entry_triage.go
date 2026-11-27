package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

const (
	entryTriageMinFunctions = 6
	entryTriageMaxFunctions = 128
	entryTriageBatchSize    = 8
	entryTriageMaxLines     = 75
	entryTriageMaxLeads     = 6
	entryTriageMaxPerFileA  = 16
	entryTriageMaxPerFileB  = 4
	entryTriageBucketAShare = 96
	entryTriageBatchTimeout = 150 * time.Second

	// triageOrderingDisclosure explicitly records OP-TEE-oriented ordering heuristics
	// used to prioritize candidate entry points; cross-project benefit requires
	// separate evaluation on non-OP-TEE repositories.
	triageOrderingDisclosure = "Candidate entry prioritization includes OP-TEE-oriented path/prefix heuristics (core/, syscall_, entry_, tee_entry_, pta_, ldelf_, tee_mmu_, spmc_); cross-project effectiveness must be validated separately on non-OP-TEE benchmarks."
)

type entryFunctionSlice struct {
	SymbolID  artifacts.SymbolID
	Name      string
	Path      string
	StartLine int
	EndLine   int
	Body      string
	Score     int
}

type entryTriageResponse struct {
	Candidates []entryTriageCandidate `json:"candidates"`
}

type entryTriageCandidate struct {
	File             string   `json:"file"`
	Symbol           string   `json:"symbol"`
	StartLine        int      `json:"start_line"`
	EndLine          int      `json:"end_line"`
	Severity         string   `json:"severity"`
	SecurityQuestion string   `json:"security_question"`
	Reason           []string `json:"reason"`
	RelatedTWEs      []string `json:"related_twes"`
}

var cFuncDefPattern = regexp.MustCompile(`^(?:static\s+|inline\s+|__weak\s+|const\s+|struct\s+\w+\s*\*?\s*|enum\s+\w+\s+|unsigned\s+|signed\s+|[A-Za-z_]\w*\s*\*?\s+)+([A-Za-z_]\w*)\s*\([^;]*$`)

func isCoreEntryFunctionName(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{
		"syscall_", "entry_", "tee_entry_", "pta_", "ta_", "user_ta_",
		"spmc_", "ldelf_", "tee_mmu_", "mobj_", "copy_in_", "copy_out_",
		"set_rmem_", "set_tmem_", "set_fmem_", "ecall_", "ocall_",
		"tee_svc_", "tee_ta_", "ree_fs_", "rpmb_fs_", "shdr_",
	} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	for _, sub := range []string{
		"_invoke_", "_open_session", "_close_session", "_ioctl", "_handler", "_dispatch",
		"_populate", "_derive", "_verify", "_decrypt", "_encrypt", "_map_param",
	} {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// isDirectExternalEntry identifies functions that directly receive untrusted
// normal-world, TA, or cross-world caller inputs (Bucket A in bounded stratified triage).
func isDirectExternalEntry(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{
		"syscall_", "entry_", "tee_entry_", "ecall_", "ocall_",
		"ldelf_syscall_", "spmc_", "pta_", "tee_mmu_", "tee_svc_",
	} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	for _, sub := range []string{
		"_invoke_command", "_open_session", "_close_session", "_ioctl", "_map_param", "_check_access",
	} {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// HasCoreEntrySurfaces reports whether repoRoot contains enough Tier-2 core
// trust-boundary entry functions to run bounded stratified entry triage even
// when CodeQL boundary_topology.v1.json could not be built.
func HasCoreEntrySurfaces(repoRoot string) bool {
	if repoRoot == "" {
		return false
	}
	entries, _ := collectCoreEntryFunctions(repoRoot, "", artifacts.BoundaryTopology{})
	return len(entries) >= entryTriageMinFunctions
}

func collectCoreEntryFunctions(repoRoot, runDir string, topo artifacts.BoundaryTopology) ([]entryFunctionSlice, int) {
	if repoRoot == "" {
		return nil, 0
	}

	fileBridgeScore := map[string]int{}
	for _, br := range topo.StructFieldBridges {
		if strings.HasPrefix(br.Field, "(unnamed ") {
			continue
		}
		seen := map[string]bool{}
		for _, id := range br.DirectWriters {
			if fp := symbolIDPath(id); fp != "" {
				seen[fp] = true
			}
		}
		for _, id := range br.NonWriteAccessors {
			if fp := symbolIDPath(id); fp != "" {
				seen[fp] = true
			}
		}
		w := 1
		if br.CrossModule {
			w = 3
		} else if len(seen) >= 2 {
			w = 2
		}
		for fp := range seen {
			fileBridgeScore[fp] += w
		}
	}

	type rawEntry struct {
		symID     artifacts.SymbolID
		name      string
		path      string
		startLine int
		score     int
	}
	seenKey := map[string]bool{}
	var candidates []rawEntry

	addCandidate := func(symID artifacts.SymbolID, name, relPath string, startLine, bonus int) {
		relPath = filepath.ToSlash(strings.TrimPrefix(relPath, "./"))
		if relPath == "" || name == "" || startLine <= 0 {
			return
		}
		tier := scoutPathPriorityTier(relPath)
		if tier < 2 {
			return
		}
		if !isCoreEntryFunctionName(name) && bonus == 0 {
			return
		}
		key := relPath + "::" + name
		if seenKey[key] {
			return
		}
		seenKey[key] = true
		if symID == "" {
			symID = artifacts.SymbolID(fmt.Sprintf("cpp:%s:%d:%s()", relPath, startLine, name))
		}
		score := tier*1000 + fileBridgeScore[relPath]*4 + bonus
		if strings.HasPrefix(strings.ToLower(name), "syscall_") || strings.HasPrefix(strings.ToLower(name), "entry_") || strings.HasPrefix(strings.ToLower(name), "tee_entry_") {
			score += 80
		}
		candidates = append(candidates, rawEntry{
			symID:     symID,
			name:      name,
			path:      relPath,
			startLine: startLine,
			score:     score,
		})
	}

	// Source 1: Indexed RepoFacts symbols (preferred when available).
	if runDir != "" {
		var facts artifacts.RepoFacts
		if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err == nil && len(facts.Symbols) > 0 {
			for _, sym := range facts.Symbols {
				if isCoreEntryFunctionName(sym.Name) {
					addCandidate(sym.SymbolID, sym.Name, sym.File, sym.StartLine, 30)
				}
			}
		}
	}

	// Source 2: Topology entry closures in Tier-2 trust-boundary files.
	for _, c := range topo.EntryClosures {
		if scoutPathPriorityTier(c.RootPath) == 2 && (isCoreEntryFunctionName(c.RootName) || fileBridgeScore[c.RootPath] >= 10) {
			addCandidate(c.RootSymbolID, c.RootName, c.RootPath, c.RootStartLine, 20)
		}
	}

	// Source 3: Pure-Go source tree scan fallback when RepoFacts & topology are absent (e.g. CodeQL DB failure).
	if len(candidates) < entryTriageMinFunctions {
		_ = filepath.WalkDir(repoRoot, func(fullPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				base := d.Name()
				if strings.HasPrefix(base, ".") || base == "out" || base == "build" || base == "scripts" || base == "documentation" || base == "datasets" || base == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".c") {
				return nil
			}
			rel, rerr := filepath.Rel(repoRoot, fullPath)
			if rerr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if scoutPathPriorityTier(rel) < 2 {
				return nil
			}
			data, rerr := os.ReadFile(fullPath)
			if rerr != nil || len(data) > 512*1024 {
				return nil
			}
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if len(line) == 0 || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '/' || line[0] == '*' {
					continue
				}
				m := cFuncDefPattern.FindStringSubmatch(line)
				if len(m) != 2 {
					continue
				}
				name := m[1]
				if !isCoreEntryFunctionName(name) {
					continue
				}
				// Confirm a '{' opens within the next 6 lines (definition, not prototype).
				hasBrace := strings.Contains(line, "{")
				for j := i + 1; !hasBrace && j < len(lines) && j <= i+6; j++ {
					if strings.Contains(lines[j], ";") {
						break
					}
					if strings.Contains(lines[j], "{") {
						hasBrace = true
					}
				}
				if hasBrace {
					addCandidate("", name, rel, i+1, 10)
				}
			}
			return nil
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].path != candidates[j].path {
			return candidates[i].path < candidates[j].path
		}
		if candidates[i].startLine != candidates[j].startLine {
			return candidates[i].startLine < candidates[j].startLine
		}
		return candidates[i].name < candidates[j].name
	})
	candidateTotal := len(candidates)

	// Two-tier bounded stratified round-robin:
	// Bucket A (direct external trust-boundary entries) gets up to 75% of slots (max 16/file).
	// Bucket B (secondary internal boundary/bridge functions) fills the remaining 25% (max 4/file).
	pickRoundRobin := func(pool []rawEntry, maxPerFile, limit int, already map[string]bool) []rawEntry {
		byFile := map[string][]rawEntry{}
		var fileOrder []string
		for _, c := range pool {
			k := c.path + "::" + c.name
			if already[k] {
				continue
			}
			if _, exists := byFile[c.path]; !exists {
				fileOrder = append(fileOrder, c.path)
			}
			if len(byFile[c.path]) < maxPerFile {
				byFile[c.path] = append(byFile[c.path], c)
			}
		}
		var res []rawEntry
		for round := 0; len(res) < limit; round++ {
			progressed := false
			for _, fp := range fileOrder {
				if round < len(byFile[fp]) {
					c := byFile[fp][round]
					res = append(res, c)
					already[c.path+"::"+c.name] = true
					progressed = true
					if len(res) >= limit {
						break
					}
				}
			}
			if !progressed {
				break
			}
		}
		return res
	}

	var bucketA, bucketB []rawEntry
	for _, c := range candidates {
		if isDirectExternalEntry(c.name) {
			bucketA = append(bucketA, c)
		} else {
			bucketB = append(bucketB, c)
		}
	}
	chosen := map[string]bool{}
	picked := pickRoundRobin(bucketA, entryTriageMaxPerFileA, entryTriageBucketAShare, chosen)
	if rem := entryTriageMaxFunctions - len(picked); rem > 0 {
		picked = append(picked, pickRoundRobin(bucketB, entryTriageMaxPerFileB, rem, chosen)...)
	}
	if rem := entryTriageMaxFunctions - len(picked); rem > 0 {
		picked = append(picked, pickRoundRobin(bucketA, entryTriageMaxPerFileA*2, rem, chosen)...)
	}

	// Read function bodies from disk.
	fileCache := map[string][]string{}
	var out []entryFunctionSlice
	for _, c := range picked {
		lines, ok := fileCache[c.path]
		if !ok {
			data, err := os.ReadFile(filepath.Join(repoRoot, c.path))
			if err != nil {
				fileCache[c.path] = nil
				continue
			}
			lines = strings.Split(string(data), "\n")
			fileCache[c.path] = lines
		}
		if len(lines) == 0 || c.startLine < 1 || c.startLine > len(lines) {
			continue
		}
		endLine := extractCFunctionEndLine(lines, c.startLine, entryTriageMaxLines)
		var body strings.Builder
		for n := c.startLine; n <= endLine; n++ {
			fmt.Fprintf(&body, "%d: %s\n", n, lines[n-1])
		}
		out = append(out, entryFunctionSlice{
			SymbolID:  c.symID,
			Name:      c.name,
			Path:      c.path,
			StartLine: c.startLine,
			EndLine:   endLine,
			Body:      body.String(),
			Score:     c.score,
		})
	}
	return out, candidateTotal
}

func extractCFunctionEndLine(lines []string, startLine, maxLines int) int {
	if maxLines <= 0 {
		maxLines = entryTriageMaxLines
	}
	limit := startLine + maxLines - 1
	if limit > len(lines) {
		limit = len(lines)
	}
	depth := 0
	sawOpen := false
	for n := startLine; n <= limit; n++ {
		line := lines[n-1]
		for _, ch := range line {
			switch ch {
			case '{':
				depth++
				sawOpen = true
			case '}':
				if sawOpen {
					depth--
					if depth <= 0 {
						return n
					}
				}
			}
		}
	}
	return limit
}

func planEntryTriageBatches(budget Budget, pendingScouts, batchTotal int, previous map[int]TriageBatchRecord) map[int]bool {
	// Each unfinished Scout needs at least one source-read round and one
	// response round. Bound triage before dispatch so worker scheduling cannot
	// consume that allowance or choose which batch receives the final slot.
	allowance := max(0, budget.MaxReconRounds-budget.ReconRoundsUsed-2*max(0, pendingScouts))
	scheduled := map[int]bool{}
	for i := 0; i < batchTotal && allowance > 0; i++ {
		if previous[i].Status == "succeeded" {
			continue
		}
		scheduled[i] = true
		allowance--
	}
	return scheduled
}

// runEntryTriage runs bounded stratified entry triage over up to
// entryTriageMaxFunctions core trust-boundary entry functions in stateless
// single-turn batches. Each batch's status (succeeded/failed/skipped_unrun) is
// persisted in the sharded checkpoint so --resume reuses succeeded batches and
// retries incomplete ones. Promoted candidates go through the same openLead
// validation and audit_leads.jsonl persistence path as BoundaryScout leads.
func (sc *shardedCoordinator) runEntryTriage(ctx context.Context, topo artifacts.BoundaryTopology, workers int) (int, bool) {
	entries, candidateTotal := collectCoreEntryFunctions(sc.cfg.RepoRoot, sc.cfg.RunDir, topo)
	if len(entries) < entryTriageMinFunctions {
		return 0, true
	}

	var batches [][]entryFunctionSlice
	for i := 0; i < len(entries); i += entryTriageBatchSize {
		end := i + entryTriageBatchSize
		if end > len(entries) {
			end = len(entries)
		}
		batches = append(batches, entries[i:end])
	}

	sc.mu.Lock()
	pendingScouts := 0
	for _, dossier := range selectScoutDossiers(topo, closuresPerScout) {
		if !sc.completedScouts[dossier.Bucket] {
			pendingScouts++
		}
	}
	scheduled := planEntryTriageBatches(sc.budget, pendingScouts, len(batches), sc.triageBatches)
	if sc.triageBatches == nil {
		sc.triageBatches = map[int]TriageBatchRecord{}
	}
	skipped := false
	for i := range batches {
		if sc.triageBatches[i].Status == "succeeded" || scheduled[i] {
			continue
		}
		const reason = "recon_rounds_reserved_for_scouts"
		sc.triageBatches[i] = TriageBatchRecord{BatchIndex: i, Status: "skipped_unrun", Reason: reason}
		sc.recordShardFailureLocked(fmt.Sprintf("triage:batch-%02d", i+1), reason, nil)
		skipped = true
	}
	if skipped {
		if err := sc.saveCheckpointLocked(false, "", nil); err != nil {
			sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", err)
		}
	}
	sc.mu.Unlock()

	distinctFiles := map[string]bool{}
	for _, e := range entries {
		distinctFiles[e.Path] = true
	}

	triageCtx := ctx
	var cancelTriage context.CancelFunc = func() {}
	triageBudget := time.Duration(0)
	if sc.budget.WallClock > 0 {
		triageBudget = time.Duration(float64(sc.budget.WallClock) * 0.35)
		if triageBudget < 2*time.Minute && sc.budget.WallClock >= 2*time.Minute {
			triageBudget = 2 * time.Minute
		}
		triageCtx, cancelTriage = context.WithTimeout(ctx, triageBudget)
	}
	defer cancelTriage()

	fmt.Fprintf(os.Stdout, "[planner/triage] bounded stratified triage: %d/%d candidate entry function(s) across %d file(s) in %d batch(es) (workers=%d, model=%s, budget=%s)\n",
		len(entries), candidateTotal, len(distinctFiles), len(batches), workers, sc.cfg.ScoutModel, triageBudget.Round(time.Second))

	const triageSystem = `You perform rapid defensive security triage on TEE/OS trust-boundary entry functions.
Inspect the supplied numbered C source functions for concrete, high-confidence vulnerabilities:
- Missing OR flawed bounds, length, offset, or integer-overflow checks on untrusted normal-world/TA/caller inputs (Flow)
- Missing OR flawed authentication, permission, type, curve/key-parameter, or address-space guards — INCLUDING subtle logic bugs inside existing checks such as loops stepping by page/block/chunk size from an unaligned start address (skipping the tail page/bytes), off-by-one range checks, or checking a different expression than what is later used (Guard)
- Broken state-machine transitions, handle/object lifecycle errors, or unvalidated state reuse (State)
- Sensitive secret/pointer/memory leakage on error or output paths (Leakage)

Return strict JSON only:
{"candidates":[{"file":"path/to/file.c","symbol":"func_name","start_line":10,"end_line":40,"severity":"high|medium","security_question":"Concrete question naming the exact missing check and security impact","reason":["Specific code-grounded reason citing line numbers"],"related_twes":["TWE-FLOW-001"]}]}

Rules:
- Only report concrete bugs evidenced directly in the supplied code; if none are clearly suspicious, return {"candidates":[]}.
- At most 3 candidates per batch. Prefer concrete, exploitable boundary flaws over minor style or defensive-hardening nitpicks.`

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for bIdx, batch := range batches {
		sc.mu.Lock()
		prev, hasPrev := sc.triageBatches[bIdx]
		sc.mu.Unlock()
		if hasPrev && prev.Status == "succeeded" {
			continue
		}
		if !scheduled[bIdx] {
			continue
		}

		wg.Add(1)
		go func(idx int, funcs []entryFunctionSlice) {
			defer wg.Done()
			batchLabel := fmt.Sprintf("triage:batch-%02d", idx+1)
			recordBatch := func(status, reason string, roundNum int, cands []TriageGroundedCandidate, err error) {
				sc.mu.Lock()
				if sc.triageBatches == nil {
					sc.triageBatches = map[int]TriageBatchRecord{}
				}
				sc.triageBatches[idx] = TriageBatchRecord{
					BatchIndex: idx,
					Status:     status,
					Reason:     reason,
					Round:      roundNum,
					Candidates: cands,
				}
				if status != "succeeded" {
					sc.recordShardFailureLocked(batchLabel, reason, err)
				}
				if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
					sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
				}
				sc.mu.Unlock()
			}

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-triageCtx.Done():
				reason := "budget_exhausted"
				if ctx.Err() != nil {
					reason = "cancelled"
				}
				recordBatch("skipped_unrun", reason, 0, nil, triageCtx.Err())
				return
			}
			if triageCtx.Err() != nil || sc.wallClockExhausted() {
				reason := "budget_exhausted"
				if ctx.Err() != nil {
					reason = "cancelled"
				}
				recordBatch("skipped_unrun", reason, 0, nil, triageCtx.Err())
				return
			}

			var user strings.Builder
			fmt.Fprintf(&user, "=== ENTRY TRIAGE BATCH %d/%d ===\n", idx+1, len(batches))
			for i, fn := range funcs {
				fmt.Fprintf(&user, "\n--- [%d] %s :: %s (lines %d-%d) ---\n%s", i+1, fn.Path, fn.Name, fn.StartLine, fn.EndLine, fn.Body)
			}

			roundNum := sc.allocRound(true)
			if roundNum == 0 {
				recordBatch("skipped_unrun", "round_budget_exhausted", 0, nil, nil)
				return
			}
			agentID := fmt.Sprintf("triage-%02d", idx+1)
			_ = sc.cfg.Events.Emit(events.PlannerRoundStarted(sc.cfg.RunID, agentID, roundNum))

			batchCtx, cancelBatch := context.WithTimeout(triageCtx, entryTriageBatchTimeout)
			resp, inTok, outTok, err := sc.askShardLLM(batchCtx, sc.cfg.ScoutClient, sc.cfg.ScoutModel, sc.cfg.ScoutTemperature, sc.cfg.ScoutMaxOutputTokens, agentID, roundNum, true, false, triageSystem, user.String())
			cancelBatch()
			if err != nil {
				reason := "llm_error"
				switch {
				case llm.IsPolicyRefusal(err):
					reason = "policy_refusal"
				case errors.Is(err, errReplyBudget):
					reason = "budget_exhausted"
				case errors.Is(err, context.DeadlineExceeded):
					reason = "timeout"
				case errors.Is(err, context.Canceled):
					reason = "cancelled"
				}
				_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
				recordBatch("failed", reason, roundNum, nil, err)
				return
			}

			var parsed entryTriageResponse
			if uerr := json.Unmarshal([]byte(extractJSONObject(resp.Text)), &parsed); uerr != nil || parsed.Candidates == nil {
				if uerr == nil {
					uerr = fmt.Errorf("triage response must include a candidates array")
				}
				_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, 0, 0))
				recordBatch("failed", "invalid_json", roundNum, nil, uerr)
				return
			}

			// Persist each triaged function snippet as a real read_file round observation
			// with content-addressed blob and canonical MakeObservationRef so downstream
			// leads and contracts can trace the exact source text the model saw.
			roundRec := artifacts.RoundRecord{
				Round:     roundNum,
				Thought:   fmt.Sprintf("bounded stratified triage batch %d/%d", idx+1, len(batches)),
				TokensIn:  inTok,
				TokensOut: outTok,
			}
			obsByFunc := map[string]string{}
			sc.mu.Lock()
			if sc.mutatingRounds == nil {
				sc.mutatingRounds = map[int]bool{}
			}
			sc.mutatingRounds[roundNum] = true
			for fIdx, fn := range funcs {
				rfArgs, _ := json.Marshal(map[string]any{"path": fn.Path, "start": fn.StartLine, "end": fn.EndLine})
				outBlob := events.BestEffortRef(sc.cfg.Blobs, []byte(fn.Body))
				body, cutHere := excerpt(fn.Body, outBlob)
				ref := MakeObservationRef(sc.cfg.RunID, sc.cfg.SampleIndex, roundNum, fIdx, outBlob)

				sc.observations.Record(ref, true)
				sc.observedPaths[fn.Path] = true
				sc.recon.ObserveSourceOutput("read_file", rfArgs, body, true)
				obsByFunc[fn.Path+"::"+fn.Name] = ref

				roundRec.Actions = append(roundRec.Actions, artifacts.RoundAction{Name: "read_file", Args: rfArgs})
				roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
					Name: "read_file", OK: true, Ref: ref, OutputBlob: outBlob, ActionIndex: fIdx,
					Phase: PhaseReconnaissance, Output: body, Truncated: cutHere,
				})
				_ = sc.cfg.Events.Emit(events.PlannerObservationRecorded(
					sc.cfg.RunID, agentID, "read_file", roundNum, sc.cfg.SampleIndex, true, ref, outBlob))
			}
			persistErr := sc.state.AppendRoundAndPersist(roundRec, sc.roundsLog)
			if persistErr == nil {
				delete(sc.mutatingRounds, roundNum)
			}
			sc.mu.Unlock()
			_ = sc.cfg.Events.Emit(events.PlannerRoundCompleted(sc.cfg.RunID, agentID, roundNum, len(roundRec.Actions), len(roundRec.Observations)))
			if persistErr != nil {
				recordBatch("failed", "persist_error", roundNum, nil, persistErr)
				return
			}

			var batchCands []TriageGroundedCandidate
			for _, cand := range parsed.Candidates {
				if strings.TrimSpace(cand.SecurityQuestion) == "" {
					continue
				}
				candFile := filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(cand.File), "src/"))
				candSym := strings.TrimSpace(cand.Symbol)
				var matched *entryFunctionSlice
				for i := range funcs {
					if funcs[i].Name == candSym && (candFile == "" || funcs[i].Path == candFile || strings.HasSuffix(funcs[i].Path, "/"+candFile)) {
						matched = &funcs[i]
						break
					}
				}
				if matched == nil {
					continue
				}
				ref := obsByFunc[matched.Path+"::"+matched.Name]
				batchCands = append(batchCands, TriageGroundedCandidate{
					File:             matched.Path,
					Symbol:           matched.Name,
					SymbolID:         matched.SymbolID,
					StartLine:        matched.StartLine,
					EndLine:          matched.EndLine,
					Score:            matched.Score,
					Severity:         strings.TrimSpace(cand.Severity),
					SecurityQuestion: strings.TrimSpace(cand.SecurityQuestion),
					Reason:           append([]string(nil), cand.Reason...),
					RelatedTWEs:      append([]string(nil), cand.RelatedTWEs...),
					ObsRef:           ref,
				})
			}
			recordBatch("succeeded", "", roundNum, batchCands, nil)
		}(bIdx, batch)
	}
	wg.Wait()

	// Gather all candidates from succeeded batches (reused + newly completed) and compute coverage summary.
	sc.mu.Lock()
	var collected []TriageGroundedCandidate
	summary := &TriageSummary{
		Mode:               "bounded_stratified_entry_triage",
		CandidateTotal:     candidateTotal,
		SelectedTotal:      len(entries),
		BatchTotal:         len(batches),
		FailureReasons:     map[string]int{},
		OrderingDisclosure: triageOrderingDisclosure,
	}
	for bIdx := 0; bIdx < len(batches); bIdx++ {
		rec, ok := sc.triageBatches[bIdx]
		if !ok {
			summary.UnrunBatches++
			summary.FailureReasons["unrun"]++
			continue
		}
		switch rec.Status {
		case "succeeded":
			summary.SucceededBatches++
			collected = append(collected, rec.Candidates...)
		case "skipped_unrun":
			summary.UnrunBatches++
			r := rec.Reason
			if r == "" {
				r = "skipped_unrun"
			}
			summary.FailureReasons[r]++
		default:
			summary.FailedBatches++
			r := rec.Reason
			if r == "" {
				r = "failed"
			}
			summary.FailureReasons[r]++
		}
	}
	allBatchesSucceeded := summary.SucceededBatches == summary.BatchTotal

	// Deterministic total-order sort independent of worker count or response timing.
	sevRank := func(s string) int {
		if strings.EqualFold(strings.TrimSpace(s), "high") {
			return 2
		}
		return 1
	}
	sort.SliceStable(collected, func(i, j int) bool {
		si, sj := sevRank(collected[i].Severity), sevRank(collected[j].Severity)
		if si != sj {
			return si > sj
		}
		if collected[i].Score != collected[j].Score {
			return collected[i].Score > collected[j].Score
		}
		if collected[i].File != collected[j].File {
			return collected[i].File < collected[j].File
		}
		if collected[i].StartLine != collected[j].StartLine {
			return collected[i].StartLine < collected[j].StartLine
		}
		if collected[i].Symbol != collected[j].Symbol {
			return collected[i].Symbol < collected[j].Symbol
		}
		return collected[i].SecurityQuestion < collected[j].SecurityQuestion
	})

	// Track files/symbols already opened in prior runs (for --resume idempotency).
	usedFileCount := map[string]int{}
	existingTarget := map[artifacts.SymbolID]bool{}
	for _, existing := range sc.state.AuditLeads {
		if existing.RunID == sc.cfg.RunID && existing.SampleIndex == sc.cfg.SampleIndex {
			for _, id := range existing.TargetSymbolIDs {
				existingTarget[id] = true
				if fp := symbolIDPath(id); fp != "" {
					usedFileCount[fp]++
				}
			}
		}
	}

	// Promote up to entryTriageMaxLeads diverse leads (max 2 per file) through the
	// unified openLead validation and audit_leads.jsonl persistence path.
	promoted := 0
	for _, gc := range collected {
		if promoted >= entryTriageMaxLeads || len(sc.state.AuditLeads) >= maxShardedLeads {
			break
		}
		if existingTarget[gc.SymbolID] || usedFileCount[gc.File] >= 2 {
			continue
		}
		reason := gc.Reason
		if len(reason) == 0 {
			reason = []string{fmt.Sprintf("Bounded stratified triage flagged %s (%s:%d-%d)", gc.Symbol, gc.File, gc.StartLine, gc.EndLine)}
		}
		payload := OpenAuditLeadPayload{
			SecurityQuestion: gc.SecurityQuestion,
			TargetSymbolIDs:  []artifacts.SymbolID{gc.SymbolID},
			Reason:           reason,
			ReasonFactRefs:   []string{gc.ObsRef},
			Uncertainty:      "medium",
			RelatedTWEs:      gc.RelatedTWEs,
		}
		rawArgs, _ := json.Marshal(payload)
		lead, res := openLead(sc.cfg, sc.recon, sc.observations, rawArgs, sc.nextRound, sc.state)
		if !res.OK {
			continue
		}
		sc.state.AuditLeads = append(sc.state.AuditLeads, lead)
		existingTarget[gc.SymbolID] = true
		usedFileCount[gc.File]++
		promoted++
	}
	summary.PromotedLeads = promoted
	sc.triageSummary = summary
	if sc.cfg.RunDir != "" {
		_ = runfs.WriteJSON(filepath.Join(runfs.PlannerDir(sc.cfg.RunDir), "triage_summary.json"), summary)
	}
	if cpErr := sc.saveCheckpointLocked(false, "", nil); cpErr != nil {
		sc.recordShardFailureLocked("checkpoint", "checkpoint_write_error", cpErr)
	}
	sc.mu.Unlock()

	fmt.Fprintf(os.Stdout, "[planner/triage] bounded stratified triage finished: batches=%d/%d succeeded (%d failed, %d unrun), promoted %d/%d candidate(s)\n",
		summary.SucceededBatches, summary.BatchTotal, summary.FailedBatches, summary.UnrunBatches, promoted, len(collected))
	return promoted, allBatchesSucceeded
}

func extractJSONObject(text string) string {
	s := strings.TrimSpace(text)
	if start := strings.IndexByte(s, '{'); start >= 0 {
		if end := strings.LastIndexByte(s, '}'); end > start {
			return s[start : end+1]
		}
	}
	return s
}
