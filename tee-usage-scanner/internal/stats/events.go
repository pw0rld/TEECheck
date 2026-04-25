package stats

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// plannerEventFold is the result of folding planner-relevant events
// from runDir/events.jsonl. It carries only the signals that events
// can actually supply — candidate count, path validity, etc. still
// come from the evidence bundle.
type plannerEventFold struct {
	HasPlannerEvents bool
	RoundsUsed       int            // distinct round numbers seen
	TokensUsed       int            // sum of all planner llm_call_completed tokens
	ActionMix        map[string]int // tool_name histogram (excludes loop-rejected; see below)
	TokensByRound    []int          // index = round-1; sum across all llm calls in that round
}

// foldPlannerEvents reads runDir/events.jsonl and folds planner
// signals from it. Returns ok=false when the file is absent or
// contains no planner events — callers should fall back to artifacts.
//
// Semantic note vs rounds.jsonl:
//   - ActionMix counts only actions that actually executed. Actions
//     rejected by the loop detector emit no tool_call_started event,
//     so they are absent from the events stream. The rounds.jsonl
//     fallback counts attempted actions (rejected ones included),
//     which is a different, looser signal.
//   - RoundsUsed is the count of distinct round numbers that emitted
//     at least one planner_round_started or _completed event. This
//     matches the budget's RoundsUsed for non-error runs.
//   - TokensUsed sums tokens_in + tokens_out across every
//     llm_call_completed whose agent starts with "planner". Future
//     expert/challenger/verifier llm events stay outside this fold.
//
// Malformed JSON lines are skipped silently — the same robustness
// the recorder applies during seq recovery.
func foldPlannerEvents(runDir string) (plannerEventFold, bool, error) {
	fold := plannerEventFold{ActionMix: map[string]int{}}

	path := filepath.Join(runDir, "events.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fold, false, nil
		}
		return fold, false, err
	}
	defer f.Close()

	roundSet := map[int]bool{}
	tokensByRound := map[int]int{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		switch e.Type {
		case events.TypePlannerRoundStarted, events.TypePlannerRoundCompleted:
			if e.Round > 0 {
				roundSet[e.Round] = true
				fold.HasPlannerEvents = true
			}
		case events.TypeLLMCallCompleted:
			if !isPlannerAgent(e.Agent) {
				continue
			}
			tokens := e.TokensIn + e.TokensOut
			fold.TokensUsed += tokens
			if e.Round > 0 {
				tokensByRound[e.Round] += tokens
			}
			fold.HasPlannerEvents = true
		case events.TypeToolCallCompleted:
			if !isPlannerAgent(e.Agent) {
				continue
			}
			if e.ToolName != "" {
				fold.ActionMix[e.ToolName]++
			}
			fold.HasPlannerEvents = true
		}
	}
	if err := sc.Err(); err != nil {
		return fold, fold.HasPlannerEvents, err
	}

	fold.RoundsUsed = len(roundSet)

	// Materialize TokensByRound array indexed by round-1, padding
	// any missing rounds with zero so positional consumers
	// (e.g. graphs that plot per-round) keep their ordering.
	maxRound := 0
	for r := range tokensByRound {
		if r > maxRound {
			maxRound = r
		}
	}
	if maxRound > 0 {
		fold.TokensByRound = make([]int, maxRound)
		for r, t := range tokensByRound {
			if r >= 1 && r <= maxRound {
				fold.TokensByRound[r-1] = t
			}
		}
	}

	return fold, fold.HasPlannerEvents, nil
}

// isPlannerAgent returns true if agent looks like a planner instance
// ("planner-001", "planner-002", ...). Any non-planner llm_call /
// tool_call event is skipped during planner stat folding so future
// expert/challenger/verifier events don't pollute these numbers.
func isPlannerAgent(agent string) bool {
	return strings.HasPrefix(agent, "planner")
}
