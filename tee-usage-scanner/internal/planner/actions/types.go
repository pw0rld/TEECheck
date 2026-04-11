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

// fail is a helper for handlers to construct an error result.
func fail(name, msg string) ActionResult {
	return ActionResult{Name: name, OK: false, Error: msg}
}
