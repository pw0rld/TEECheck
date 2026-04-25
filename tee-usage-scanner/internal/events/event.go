// Package events defines the typed event stream emitted by TEECheck
// agents during a run. Events are append-only facts (not prompts or
// transcripts) that downstream consumers — stats, replay, review UI —
// fold over to derive metrics and reconstruct what happened.
//
// Design choices captured in docs/EVENT_SCHEMA.md:
//   - flat tagged-struct, not interface sum-type (jq/grep friendly)
//   - prompt/response/tool-args bodies live in a content-addressed
//     blob store; the event only carries the sha256 reference
//   - seq is monotonic per recorder, recovered from existing file on
//     re-open so resumed runs continue numbering without gaps
package events

import "time"

// Event types. Stable strings — schema-breaking changes require a
// schema version bump in docs/EVENT_SCHEMA.md.
const (
	TypeRunStarted             = "run_started"
	TypeRunCompleted           = "run_completed"
	TypePlannerRoundStarted    = "planner_round_started"
	TypePlannerRoundCompleted  = "planner_round_completed"
	TypeLLMCallStarted         = "llm_call_started"
	TypeLLMCallCompleted       = "llm_call_completed"
	TypeToolCallStarted        = "tool_call_started"
	TypeToolCallCompleted      = "tool_call_completed"
)

// Event is the single shape written to events.jsonl. Only fields
// relevant to the event's Type are populated; the rest stay at their
// zero value and are omitted from JSON via omitempty.
//
// New event types should reuse existing fields where possible. Add a
// new field only when no existing field carries the right semantics.
type Event struct {
	// Common
	Seq    int64     `json:"seq"`
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	RunID  string    `json:"run_id"`
	Agent  string    `json:"agent,omitempty"`
	CaseID string    `json:"case_id,omitempty"`
	Round  int       `json:"round,omitempty"`

	// run_started
	Target string `json:"target,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Focus  string `json:"focus,omitempty"`

	// llm_call_*
	Model        string `json:"model,omitempty"`
	TokensIn     int    `json:"tokens_in,omitempty"`
	TokensOut    int    `json:"tokens_out,omitempty"`
	PromptBlob   string `json:"prompt_blob,omitempty"`
	ResponseBlob string `json:"response_blob,omitempty"`

	// tool_call_*
	ToolName       string `json:"tool_name,omitempty"`
	ToolArgsBlob   string `json:"tool_args_blob,omitempty"`
	ToolOK         bool   `json:"tool_ok,omitempty"`
	ToolDurationMs int64  `json:"tool_duration_ms,omitempty"`

	// planner_round_completed
	ActionCount      int `json:"action_count,omitempty"`
	ObservationCount int `json:"observation_count,omitempty"`

	// run_completed, *_started errors
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Constructors — keep callers from misfiling event-type-specific
// fields. Each returns a partially-populated Event; the recorder
// fills in Seq and Time.

func RunStarted(runID, target, mode, focus string) Event {
	return Event{
		Type:   TypeRunStarted,
		RunID:  runID,
		Target: target,
		Mode:   mode,
		Focus:  focus,
	}
}

func RunCompleted(runID, reason string, errMsg string) Event {
	return Event{
		Type:   TypeRunCompleted,
		RunID:  runID,
		Reason: reason,
		Error:  errMsg,
	}
}

func PlannerRoundStarted(runID, agent string, round int) Event {
	return Event{
		Type:  TypePlannerRoundStarted,
		RunID: runID,
		Agent: agent,
		Round: round,
	}
}

func PlannerRoundCompleted(runID, agent string, round, actionCount, observationCount int) Event {
	return Event{
		Type:             TypePlannerRoundCompleted,
		RunID:            runID,
		Agent:            agent,
		Round:            round,
		ActionCount:      actionCount,
		ObservationCount: observationCount,
	}
}

func LLMCallStarted(runID, agent, model string, round int) Event {
	return Event{
		Type:  TypeLLMCallStarted,
		RunID: runID,
		Agent: agent,
		Model: model,
		Round: round,
	}
}

func LLMCallCompleted(runID, agent, model string, round, tokensIn, tokensOut int, promptBlob, responseBlob string) Event {
	return Event{
		Type:         TypeLLMCallCompleted,
		RunID:        runID,
		Agent:        agent,
		Model:        model,
		Round:        round,
		TokensIn:     tokensIn,
		TokensOut:    tokensOut,
		PromptBlob:   promptBlob,
		ResponseBlob: responseBlob,
	}
}

func ToolCallStarted(runID, agent, toolName string, round int, toolArgsBlob string) Event {
	return Event{
		Type:         TypeToolCallStarted,
		RunID:        runID,
		Agent:        agent,
		Round:        round,
		ToolName:     toolName,
		ToolArgsBlob: toolArgsBlob,
	}
}

func ToolCallCompleted(runID, agent, toolName string, round int, ok bool, durationMs int64, errMsg string) Event {
	return Event{
		Type:           TypeToolCallCompleted,
		RunID:          runID,
		Agent:          agent,
		Round:          round,
		ToolName:       toolName,
		ToolOK:         ok,
		ToolDurationMs: durationMs,
		Error:          errMsg,
	}
}
