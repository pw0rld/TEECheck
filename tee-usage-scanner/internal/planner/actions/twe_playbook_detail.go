package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// PlaybookDetailSource supplies the full text of one TWE playbook.
// *twecontext.Catalog satisfies it structurally, so this package — and
// internal/planner with it — keeps its deliberate non-dependency on
// internal/twecontext (see planner.TWEPlaybookSummary's doc comment).
type PlaybookDetailSource interface {
	Detail(tweID string) (string, bool)
}

type twePlaybookDetailArgs struct {
	TWEID string `json:"twe_id"`
}

// TWEPlaybookDetailHandler serves the detail tier of the TWE prior knowledge.
// Every agent already carries the brief tier (id, name, family, scenario,
// look_for); this action returns the full investigation method for one TWE so
// the deep content is paid for only when the planner decides a family is
// relevant.
type TWEPlaybookDetailHandler struct {
	Source PlaybookDetailSource
}

func (h *TWEPlaybookDetailHandler) Name() string { return "twe_playbook_detail" }

func (h *TWEPlaybookDetailHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args twePlaybookDetailArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("twe_playbook_detail", fmt.Sprintf("invalid args: %v", err))
	}
	id := strings.TrimSpace(args.TWEID)
	if id == "" {
		return fail("twe_playbook_detail", "twe_id is required")
	}
	if h.Source == nil {
		return fail("twe_playbook_detail", "no TWE playbook catalog is loaded for this run")
	}
	text, ok := h.Source.Detail(id)
	if !ok {
		return fail("twe_playbook_detail", fmt.Sprintf("no playbook for %s — check the id against the brief catalog in your system prompt", id))
	}
	return ActionResult{Name: "twe_playbook_detail", OK: true, Output: text}
}
