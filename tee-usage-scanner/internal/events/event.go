// Package events defines the typed event stream emitted by TEECheck
// agents during a run. Events are append-only facts (not prompts or
// transcripts) that downstream consumers — stats, replay, review UI —
// fold over to derive metrics and reconstruct what happened.
//
// Design choices captured in docs/EVENT_SCHEMA.md:
//   - flat tagged-struct, not interface sum-type (jq/grep friendly)
//   - prompt / response / tool-args / tool-output bodies live in a
//     content-addressed blob store; the event only carries the
//     sha256 reference
//   - seq is monotonic per recorder, recovered from existing file on
//     re-open so resumed runs continue numbering without gaps
package events

import (
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// Event types. Stable strings — schema-breaking changes require a
// schema version bump in docs/EVENT_SCHEMA.md.
const (
	TypeRunStarted            = "run_started"
	TypeRunCompleted          = "run_completed"
	TypePlannerRoundStarted   = "planner_round_started"
	TypePlannerRoundCompleted = "planner_round_completed"

	TypePlannerObservationRecorded = "planner_observation_recorded"

	TypeLLMCallStarted       = "llm_call_started"
	TypeLLMCallCompleted     = "llm_call_completed"
	TypeToolCallStarted      = "tool_call_started"
	TypeToolCallCompleted    = "tool_call_completed"
	TypeStageStarted         = "stage_started"
	TypeStageCompleted       = "stage_completed"
	TypeClaimEmitted         = "claim_emitted"
	TypeValueNormalized      = "value_normalized"
	TypeBusQuery             = "bus_query"
	TypeBusQueryFailed       = "bus_query_failed"
	TypeBusResponseTruncated = "bus_response_truncated"
	TypeRunConfig            = "run_config"
	TypeSourceScopeResolved  = "source_scope_resolved"
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
	ToolExitCode   int    `json:"tool_exit_code,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`

	// tool_call_completed bodies. Stdout and stderr get separate refs
	// rather than one concatenated blob: a combined body would either
	// need framing bytes (so the ref no longer resolves to what the
	// tool actually wrote) or would lose which stream said what —
	// and stderr is where a tool explains why it failed.
	//
	// In-process planner actions have a single output stream and
	// populate ToolOutputBlob only.
	ToolOutputBlob string `json:"tool_output_blob,omitempty"`
	ToolStderrBlob string `json:"tool_stderr_blob,omitempty"`

	// Executor policy snapshot, populated only on tool_call_started
	// events emitted by the executor. Tool calls that bypass the
	// executor (today: planner ripgrep going straight through the
	// action registry) leave these zero/empty.
	Network        string `json:"network,omitempty"`
	Write          string `json:"write,omitempty"`
	TimeoutMs      int64  `json:"timeout_ms,omitempty"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty"`

	// bus_response_truncated. OriginalBytes is what the handler produced
	// before the cap; MaxOutputBytes above is the cap it hit. Both are
	// needed: "we cut something" is not the question — "how much, and was
	// it worth reading" is, and that cannot be answered from a boolean.
	OriginalBytes int `json:"original_bytes,omitempty"`

	// planner_round_completed
	ActionCount      int `json:"action_count,omitempty"`
	ObservationCount int `json:"observation_count,omitempty"`

	// planner_observation_recorded. ObservationRef is the id a downstream
	// claim cites; ToolOutputBlob (above) is both the body it resolves to and
	// the join key back to the tool_call_completed that produced it.
	//
	// This is a separate event rather than a field on tool_call_completed
	// because the ref is derived from the output body, so it exists only
	// after the action returns — and for executor-backed actions the
	// executor has already written tool_call_completed by then. A field
	// cannot be added to an event that is on disk.
	//
	// SampleIndex disambiguates --samples passes, which all restart at round
	// 1. It is omitempty, so sample 0 is absent; ObservationRef carries the
	// index in every case.
	ObservationRef string `json:"observation_ref,omitempty"`
	SampleIndex    int    `json:"sample_index,omitempty"`

	// stage_*. Stage is the pipeline stage name; DurationMs is wall
	// clock on stage_completed. Reason (below) carries the outcome,
	// using the same "completed" / "error" vocabulary as run_completed.
	Stage      string `json:"stage,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`

	// run_completed, *_started errors
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`

	// claim_emitted
	ClaimID string                 `json:"claim_id,omitempty"`
	Claim   string                 `json:"claim,omitempty"`
	Cited   []citations.CitedBytes `json:"cited,omitempty"`

	// bus_query_failed. Agent (above) is the asking end; ToAgent is the
	// name it asked for. A refused inter-agent query used to reach the
	// model as one line of prose and leave no trace at all — across six
	// runs 72 of them were refused, every one invisible here, while the
	// arbiter cited exactly those failures as its reason for capping a
	// finding at needs_review.
	ToAgent string `json:"to_agent,omitempty"`

	// value_normalized. Reason (above) carries the explanation; these
	// three carry the part a reader cannot reconstruct from prose —
	// which field, and what it said before and after.
	Field     string `json:"field,omitempty"`
	FromValue string `json:"from_value,omitempty"`
	ToValue   string `json:"to_value,omitempty"`

	// bus_query. QueryID is the join key to the stage's own dialog-*.jsonl
	// transcript; Kind and Question are inline so `grep bus_query` answers
	// "what did the agents actually ask each other" without opening a blob.
	QueryID  string `json:"query_id,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Question string `json:"question,omitempty"`

	// run_config. The process argv that produced this run, with any API key
	// value replaced. Everything else in the stream describes what the run
	// did; without this, nothing describes what it was asked to do — run-b's
	// scope had to be reconstructed by inference from the manifest.
	Command string `json:"command,omitempty"`
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

// RunConfig records the command line that started the run.
//
// It exists because run-b's launch command was recoverable only by inference:
// the manifest carried a repository and a commit that git could not have
// detected for the scanned directory, so --repo-url and --commit must have
// been passed — but which target, which run-id, which hint, and whether the
// LLM settings came from flags or the environment were all unrecorded. A run
// that cannot say how it was invoked cannot be re-run.
func RunConfig(runID, command string) Event {
	return Event{
		Type:    TypeRunConfig,
		RunID:   runID,
		Command: command,
	}
}

// SourceScopeResolved records the one tree every stage of the run reads.
//
// run_started carries the target the user named, and must: it is emitted
// before anything is fetched. But the scope is decided later, and when a
// pinned checkout is used the two differ — run-b reported a benchmark fixture
// directory as its target while every stage read a full optee_os checkout.
// Reason distinguishes the pinned checkout from the fallback, because a run
// that silently fell back is the failure this event is here to make visible.
func SourceScopeResolved(runID, root, reason string) Event {
	return Event{
		Type:   TypeSourceScopeResolved,
		RunID:  runID,
		Target: root,
		Reason: reason,
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

// PlannerObservationRecorded names one observation so a later claim can cite
// it.
//
// It is emitted by the planner after every action, whoever emitted the tool
// events for that action: an executor-backed handler has already written its
// own tool_call_completed by the time the ref exists, and a ref derived from
// the output body cannot exist before the body does. outputBlob is the join
// key back to that tool_call_completed.
//
// ok follows the stream's existing convention for tool_ok — false is omitted
// — so a reader asking "was this observation grounded" must test for true
// rather than for presence. The authoritative per-observation record is
// rounds.jsonl, where ok is always written.
func PlannerObservationRecorded(runID, agent, action string, round, sampleIndex int, ok bool, ref, outputBlob string) Event {
	return Event{
		Type:           TypePlannerObservationRecorded,
		RunID:          runID,
		Agent:          agent,
		Round:          round,
		SampleIndex:    sampleIndex,
		ToolName:       action,
		ToolOK:         ok,
		ObservationRef: ref,
		ToolOutputBlob: outputBlob,
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

// ToolCallCompleted is the constructor for in-process tool calls (the
// planner's read_file, list_dir, tree_sitter_outline, done, ...).
//
// outputBlob is required rather than optional on purpose: a completed
// event that names the tool and nothing else records that something
// happened, not what. Callers that genuinely have no output pass "".
func ToolCallCompleted(runID, agent, toolName string, round int, ok bool, durationMs int64, outputBlob, errMsg string) Event {
	return Event{
		Type:           TypeToolCallCompleted,
		RunID:          runID,
		Agent:          agent,
		Round:          round,
		ToolName:       toolName,
		ToolOK:         ok,
		ToolDurationMs: durationMs,
		ToolOutputBlob: outputBlob,
		Error:          errMsg,
	}
}

// StageStarted / StageCompleted bracket one pipeline stage.
//
// They exist because `grep stage_ events.jsonl` used to return nothing:
// only stages that happened to make an LLM call left any trace, and the
// deterministic ones (profile, TWE context, cases, mapper) left none at
// all. From the stream alone you could not tell whether they ran, how
// long they took, or which one a run died in.
func StageStarted(runID, stage string) Event {
	return Event{
		Type:  TypeStageStarted,
		RunID: runID,
		Stage: stage,
	}
}

// StageCompleted always fires, including when the stage failed —
// a stream that goes silent on failure is the case where the record
// matters most. reason uses run_completed's vocabulary: "completed"
// or "error".
func StageCompleted(runID, stage, reason string, durationMs int64, errMsg string) Event {
	return Event{
		Type:       TypeStageCompleted,
		RunID:      runID,
		Stage:      stage,
		Reason:     reason,
		DurationMs: durationMs,
		Error:      errMsg,
	}
}

// ToolCallExecutorStarted is the constructor used by the executor.
// It carries the policy snapshot so consumers can later filter or
// audit on Network/Write/Timeout without having to reach into
// blobs or stage artifacts.
func ToolCallExecutorStarted(runID, agent, toolName string, round int, toolArgsBlob, network, write string, timeoutMs int64, maxOutputBytes int) Event {
	return Event{
		Type:           TypeToolCallStarted,
		RunID:          runID,
		Agent:          agent,
		Round:          round,
		ToolName:       toolName,
		ToolArgsBlob:   toolArgsBlob,
		Network:        network,
		Write:          write,
		TimeoutMs:      timeoutMs,
		MaxOutputBytes: maxOutputBytes,
	}
}

// ClaimEmitted is the constructor for the byte-citation contract
// (A1). Each claim made by an agent (expert, challenger, verifier,
// arbiter) is paired with a list of CitedBytes that pin the claim
// to a specific region of source bytes. Stats validates these
// against repo bytes to compute typed citation metrics.
//
// claim_id is opaque and only needs to be unique within a case_id
// scope. Cited may be nil/empty for claims the agent could not
// substantiate; downstream consumers can choose to drop or flag
// uncited claims.
func ClaimEmitted(runID, agent, caseID, claimID, claim string, cited []citations.CitedBytes) Event {
	return Event{
		Type:    TypeClaimEmitted,
		RunID:   runID,
		Agent:   agent,
		CaseID:  caseID,
		ClaimID: claimID,
		Claim:   claim,
		Cited:   cited,
	}
}

// ValueNormalized records that a stage replaced a value the model
// actually produced with a different one — an off-vocabulary rating
// recovered by a corrective re-ask, or demoted to "unrated" when no
// legal value could be obtained.
//
// This event exists because the Challenger's "synthetic echo" defect
// (2026-07-28) survived four days for one reason: the rewrite left no
// trace. The artifact said "theoretical" and nothing anywhere recorded
// that the model had said "high". Any stage that rewrites model output
// should emit this rather than rewriting silently.
// BusQueryFailed records an inter-agent query that was not answered —
// because the target is not registered, or because its handler errored.
// Both are refusals from the asking agent's point of view, and a registered
// but broken agent must not be more invisible than an unregistered one.
// BusQuery records an inter-agent query that was answered.
//
// Only the refusals and the over-long answers were recorded before this, so
// the event stream held the bus's failures and none of its work. On run-b the
// verifier and the arbiter exchanged 21 questions with scanner-001; eleven
// truncation events were the only trace, and the questions themselves lived
// in a separate per-stage transcript with no shared timeline. The reasoning
// those four agents do IS the inter-agent dialogue, and it was the one part
// of the run that could not be replayed from events.jsonl.
//
// AnswerBytes is the size the asking agent was shown, after any cap — pair it
// with the bus_response_truncated event on the same query to see what a cut
// cost. QueryBlob and ResponseBlob carry the full bodies.
func BusQuery(runID, fromAgent, toAgent, caseID, queryID, kind, question string, answerBytes int, durationMs int64, queryBlob, responseBlob string) Event {
	return Event{
		Type:           TypeBusQuery,
		RunID:          runID,
		Agent:          fromAgent,
		ToAgent:        toAgent,
		CaseID:         caseID,
		QueryID:        queryID,
		Kind:           kind,
		Question:       question,
		OriginalBytes:  answerBytes,
		ToolDurationMs: durationMs,
		ToolArgsBlob:   queryBlob,
		ToolOutputBlob: responseBlob,
	}
}

func BusQueryFailed(runID, fromAgent, toAgent, caseID, reason string) Event {
	return Event{
		Type:    TypeBusQueryFailed,
		RunID:   runID,
		Agent:   fromAgent,
		ToAgent: toAgent,
		CaseID:  caseID,
		Reason:  reason,
	}
}

// BusResponseTruncated records an inter-agent answer that exceeded its cap
// and was cut down before reaching the asking agent's prompt.
//
// It exists so the cost of capping is measurable instead of assumed. A cap
// that silently trims relevant evidence and a cap that trims a handler's
// noise look identical from the outside; the only way to tell them apart is
// to record every cut with its size and go read the ones that mattered. The
// full body is at Blob.
func BusResponseTruncated(runID, fromAgent, toAgent, caseID string, originalBytes, limit int, blob string) Event {
	return Event{
		Type:           TypeBusResponseTruncated,
		RunID:          runID,
		Agent:          fromAgent,
		ToAgent:        toAgent,
		CaseID:         caseID,
		OriginalBytes:  originalBytes,
		MaxOutputBytes: limit,
		Truncated:      true,
		ToolOutputBlob: blob,
	}
}

func ValueNormalized(runID, agent, caseID, field, from, to, reason string) Event {
	return Event{
		Type:      TypeValueNormalized,
		RunID:     runID,
		Agent:     agent,
		CaseID:    caseID,
		Field:     field,
		FromValue: from,
		ToValue:   to,
		Reason:    reason,
	}
}

// ToolCallExecutorCompleted carries the additional execution facts
// the executor knows: exit code (separate from OK so a non-zero exit
// from a normally-failing tool like rg-with-no-matches stays
// machine-distinguishable from a real failure), Truncated, and the two
// output stream refs.
//
// stdoutBlob/stderrBlob are populated on the failure path too: a tool
// that errored is exactly the call someone will be diagnosing, and
// stderr is usually the only place it said why.
func ToolCallExecutorCompleted(runID, agent, toolName string, round int, ok bool, exitCode int, durationMs int64, truncated bool, stdoutBlob, stderrBlob, errMsg string) Event {
	return Event{
		Type:           TypeToolCallCompleted,
		RunID:          runID,
		Agent:          agent,
		Round:          round,
		ToolName:       toolName,
		ToolOK:         ok,
		ToolExitCode:   exitCode,
		ToolDurationMs: durationMs,
		Truncated:      truncated,
		ToolOutputBlob: stdoutBlob,
		ToolStderrBlob: stderrBlob,
		Error:          errMsg,
	}
}
