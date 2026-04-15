package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// RunConfig is the input to Run. Everything the main loop needs is
// passed explicitly — no package-level state.
type RunConfig struct {
	RunID       string
	RepoRoot    string
	RunDir      string
	Profile     PromptProfile
	Client      llm.Client
	Registry    *actions.Registry
	Budget      Budget
	Temperature float64
	// MaxActionsPerRound caps how many actions the LLM may request in
	// one round. Defaults to 3 if zero.
	MaxActionsPerRound int
	// KnowledgeRoot is the on-disk root of the TEECheck knowledge wiki
	// (typically cfg.KnowledgeRoot from the top-level config). When
	// non-empty, Run will load `wiki/obligations/*.md` and
	// `wiki/patterns/*.md` into the system prompt so the LLM sees the
	// curated review criteria alongside the sink catalog. Empty means
	// "no obligations block" — planner still runs, just without wiki
	// context.
	KnowledgeRoot string
}

// RunResult is the return value of Run. Bundle is always non-nil.
type RunResult struct {
	Bundle *artifacts.EvidenceBundle
	Err    error
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
	if cfg.Budget.MaxRounds == 0 {
		cfg.Budget = NewDefaultBudget()
	}
	if cfg.MaxActionsPerRound <= 0 {
		cfg.MaxActionsPerRound = 3
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
	systemPrompt := BuildSystemPrompt(cfg.Registry.Names(), obligations)
	roundsLog := runfs.RoundsLogPath(cfg.RunDir)

	var donePayload actions.DonePayload
	var terminationReason string
	var runErr error

loop:
	for !cfg.Budget.Exhausted() {
		cfg.Budget.ConsumeRound()
		roundNum := cfg.Budget.RoundsUsed

		roundPrompt := BuildRoundPrompt(state, cfg.Profile, cfg.Budget)

		isFinalRound := cfg.Budget.RoundsUsed == cfg.Budget.MaxRounds

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

		fmt.Fprintf(os.Stdout, "[planner] round %d/%d — calling LLM...\n", roundNum, cfg.Budget.MaxRounds)
		genReq := llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     []llm.Message{{Role: "user", Content: roundPrompt}},
			Temperature:  cfg.Temperature,
			JSONMode:     true,
		}
		genResp, err := cfg.Client.Generate(ctx, genReq)
		if err != nil {
			runErr = fmt.Errorf("round %d: llm generate: %w", roundNum, err)
			terminationReason = "llm_error"
			break
		}

		// Crude token accounting: ~4 chars per token.
		cfg.Budget.ConsumeTokens(len(systemPrompt)/4 + len(roundPrompt)/4 + len(genResp.Text)/4)

		parsed, err := ParseLLMResponse(genResp.Text)
		if err != nil {
			runErr = fmt.Errorf("round %d: %w", roundNum, err)
			terminationReason = "llm_malformed"
			state.AppendRoundAndPersist(artifacts.RoundRecord{
				Round:   roundNum,
				Thought: "<unparseable>: " + truncate(genResp.Text, 500),
			}, roundsLog)
			break
		}

		roundRec := artifacts.RoundRecord{
			Round:   roundNum,
			Thought: parsed.Thought,
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
				roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
					Name:  act.Name,
					OK:    false,
					Error: "loop detector: repeating same (action, args) — try a different action or args",
				})
				continue
			}

			fmt.Fprintf(os.Stdout, "[planner]   -> %s\n", act.Name)
			result := cfg.Registry.Run(ctx, actions.ActionRequest{
				Name:     act.Name,
				Args:     act.Args,
				RepoRoot: cfg.RepoRoot,
			})
			loopDet.Record(act.Name, argsStr)

			roundRec.Observations = append(roundRec.Observations, artifacts.RoundObservation{
				Name:       result.Name,
				OK:         result.OK,
				Output:     truncate(result.Output, 4000),
				Error:      result.Error,
				Truncated:  result.Truncated,
				DurationMs: result.DurationMs,
			})

			// Track any repo-relative path the LLM has inspected, so
			// the force-done prompt can constrain candidates[].paths.
			if result.OK {
				trackObservedPaths(act.Name, act.Args, result.Output, cfg.RepoRoot, observedPaths)
			}

			if result.Name == "done" && result.OK {
				if err := json.Unmarshal([]byte(result.Output), &donePayload); err == nil {
					state.AppendRoundAndPersist(roundRec, roundsLog)
					terminationReason = "llm_done"
					break loop
				}
			}
		}

		if err := state.AppendRoundAndPersist(roundRec, roundsLog); err != nil {
			runErr = fmt.Errorf("round %d: persist: %w", roundNum, err)
			terminationReason = "persist_error"
			break
		}
	}

	if terminationReason == "" {
		terminationReason = cfg.Budget.TerminationReason()
	}
	if terminationReason == "" {
		terminationReason = "unknown"
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
			RoundsUsed:        cfg.Budget.RoundsUsed,
			RoundsBudget:      cfg.Budget.MaxRounds,
			TokensUsed:        cfg.Budget.TokensUsed,
			WallClockMs:       time.Since(loopStartedAt).Milliseconds(),
			TerminationReason: terminationReason,
		},
		FinalSummary: donePayload.Summary,
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

	return RunResult{Bundle: bundle, Err: runErr}
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
