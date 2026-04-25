package actions

import (
	"context"
	"encoding/json"
	"fmt"
)

// DonePayload is the structured payload of the done action — the
// LLM's final summary and candidate list. The planner main loop
// (M3b) unmarshals ActionResult.Output back into this struct after
// detecting result.Name == "done".
type DonePayload struct {
	Summary    string           `json:"summary"`
	Candidates []map[string]any `json:"candidates"`
}

// DoneHandler implements the terminal `done` action. It validates
// the LLM's final payload (summary + candidates) and echoes it as
// the result Output (JSON pretty-printed). The main loop detects
// `result.Name == "done"` to stop the planner loop.
//
// candidates is intentionally typed as []map[string]any here, not as
// []artifacts.Candidate, because the LLM may include fields the
// schema does not yet know about. The main loop converts to typed
// Candidate objects when building the final EvidenceBundle.
type DoneHandler struct{}

func (DoneHandler) Name() string { return "done" }

func (DoneHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var payload DonePayload
	if err := json.Unmarshal(req.Args, &payload); err != nil {
		return fail("done", fmt.Sprintf("invalid args: %v", err))
	}

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fail("done", fmt.Sprintf("marshal payload: %v", err))
	}
	return ActionResult{
		Name:   "done",
		OK:     true,
		Output: string(out),
	}
}
