package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// DonePayload is the structured payload of the done action — the
// LLM's final summary and candidate list. The planner main loop
// (M3b) unmarshals ActionResult.Output back into this struct after
// detecting result.Name == "done".
type DonePayload struct {
	Summary        string                      `json:"summary"`
	Candidates     []map[string]any            `json:"candidates"`
	CaseInvariants []artifacts.CaseInvariantV2 `json:"case_invariants,omitempty"`

	// Investigations is the §7.5/§9.5 counterpart of Candidates: each
	// entry is a loosely-typed TWEInvestigation the LLM believes it built
	// this run (twe_ids, filled/missing roles, required evidence,
	// counterevidence, coverage gaps, tool fact refs — see
	// internal/investigations.WireInvestigation, whose JSON tags this
	// mirrors). Like Candidates, it stays []map[string]any here: the main
	// loop (internal/planner) is what converts, classifies, and grounds
	// each entry via internal/investigations before it becomes a
	// persisted artifacts.TWEInvestigation. Optional — an LLM/run that
	// found nothing worth tracking as a formal investigation this round
	// omits it entirely.
	Investigations []map[string]any `json:"investigations,omitempty"`
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
