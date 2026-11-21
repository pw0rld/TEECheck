// Package actions defines the planner action contract and the built-in
// handlers the LLM planner dispatches to during reconnaissance.
//
// An Action is a single tool invocation the LLM requests. The registry
// receives ActionRequests and returns ActionResults. Handlers parse their
// own typed arguments from the raw JSON in ActionRequest.Args.
package actions

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// ActionRequest is one tool invocation the LLM has asked for.
type ActionRequest struct {
	// Name identifies which handler to dispatch to.
	Name string `json:"name"`
	// Args is the raw JSON payload the LLM provided.
	// Each handler is responsible for unmarshalling this into its own
	// typed argument struct and validating it.
	Args json.RawMessage `json:"args"`
	// RepoRoot is the absolute path to the cloned repository. It is
	// injected by the planner, not supplied by the LLM.
	RepoRoot string `json:"-"`

	// RunDir is the absolute path to this run's artifact directory. Like
	// RepoRoot, it is injected by the planner. Fact-layer actions need it
	// to build (or reuse) the per-commit CodeQL database and persist the
	// resulting ToolFact as an explicit run artifact (§23.3).
	RunDir string `json:"-"`
	// Repository and Commit identify the pinned (repo URL, commit) a
	// fact-layer call runs against. Injected by the planner from the same
	// project identity PromptProfile carries — never supplied by the LLM,
	// which must not be trusted to name its own audit target.
	Repository string `json:"-"`
	Commit     string `json:"-"`

	// Executor is the chokepoint for subprocess-class actions
	// (ripgrep, semgrep, codeql, ...). It is non-nil for production
	// callers; in-process actions (read_file, list_dir, ...) ignore
	// the field.
	//
	// Subprocess handlers should refuse to run when Executor is nil
	// — silently falling back to an event-less local executor would
	// hide policy and observability from the run.
	Executor executor.Executor `json:"-"`
	// RunID / Agent / Round are correlation identifiers stamped onto
	// any event the executor emits for this call. Only meaningful
	// for executor-backed handlers.
	RunID string `json:"-"`
	Agent string `json:"-"`
	Round int    `json:"-"`
	// TracePolicy is populated by the live planner, never decoded from tool
	// arguments. It enforces sample-local observation and query budgets.
	TracePolicy *TracePolicy `json:"-"`
}

type TracePolicy struct {
	ObservedSymbol func(artifacts.SymbolID) bool
	TakeQuery      func() bool
	Timeout        time.Duration
}

// ActionResult is what a handler returns. It is the single observation
// format the LLM sees back.
type ActionResult struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Handler is the contract for a single planner action.
//
// Handlers must be safe to run concurrently, must honor ctx cancellation,
// and must never return an error via the Go error channel — all failures
// are reported through ActionResult.OK=false + Error so that the planner
// LLM can observe and react to them.
type Handler interface {
	Name() string
	Run(ctx context.Context, req ActionRequest) ActionResult
}

// ExecutorBacked is an optional marker implemented by handlers that
// route their work through internal/executor and therefore emit
// their own tool_call_started / tool_call_completed events. The
// planner uses this signal to skip its manual event emission for
// those actions, so the executor's events are not duplicated.
//
// In-process handlers (read_file, list_dir, tree_sitter_outline,
// done) do not implement this interface; the planner emits events
// for them on the surrounding registry call.
type ExecutorBacked interface {
	Handler
	IsExecutorBacked() bool
}

// fail is a helper for handlers to construct an error result.
func fail(name, msg string) ActionResult {
	return ActionResult{Name: name, OK: false, Error: msg}
}
