package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// factLayerQueryLocationCap bounds how many locations the compact
// observation echoes verbatim. A single fact-layer query result is
// typically a handful of flagged sites; this cap exists only to guard
// against a pathological result blowing up the round prompt — the full
// list always lives in the persisted ToolFact (ToolFactRef).
const factLayerQueryLocationCap = 20

type factLayerQueryArgs struct {
	Operation string `json:"operation"`
}

// factLayerQueryOutput is the compact observation the LLM sees back for a
// fact_layer_query call. It intentionally excludes the raw ToolFact.Result
// blob and any coverage-gap prose beyond what the fact layer itself
// disclosed — §11.2/§24: "观察结果使用 artifact refs", not the full tool
// payload re-entering the prompt. Full detail is always available at
// ToolFactRef.
type factLayerQueryOutput struct {
	ToolFactRef   string                   `json:"tool_fact_ref"`
	Status        string                   `json:"status"`
	Operation     string                   `json:"operation"`
	LocationCount int                      `json:"location_count"`
	Locations     []artifacts.ToolLocation `json:"locations,omitempty"`
	Truncated     bool                     `json:"truncated,omitempty"`
	CoverageGaps  []string                 `json:"coverage_gaps,omitempty"`
	Error         string                   `json:"error,omitempty"`
}

// FactLayerQueryHandler implements the fact_layer_query action: the
// Planner's single entry point into the structured evidence fact layer
// (§7.1, §7.5, §24). It never reasons about vulnerability status — it
// executes exactly one trustirfacts operation and returns a compact,
// artifact-referenced observation; the calling LLM decides what to do with
// a "success", "unresolved", or "unsupported" status.
//
// Engine and QueryPackDir must be set before Run is called — the caller
// constructs a *codeql.Engine, or in tests a fake satisfying
// trustirfacts.Engine, and registers a pointer to one instance holding
// its own QueryPackDir.
type FactLayerQueryHandler struct {
	Engine       trustirfacts.Engine
	QueryPackDir string
}

func (h *FactLayerQueryHandler) Name() string { return "fact_layer_query" }

func (h *FactLayerQueryHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args factLayerQueryArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("fact_layer_query", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Operation) == "" {
		return fail("fact_layer_query", fmt.Sprintf(
			"operation is required; supported operations are: %s",
			strings.Join(trustirfacts.SupportedOperationStrings(), ", ")))
	}
	// Reject an operation outside the closed vocabulary here, naming the
	// legal values. Previously nothing checked: an invented operation
	// travelled all the way into trustirfacts.Run, which returned an
	// "unsupported" ToolFact — a persisted artifact for a query that was
	// never executed, whose error text blamed the repository rather than
	// the operation. Failing at the edge with the vocabulary attached lets
	// the model correct itself on the next round.
	if !trustirfacts.IsSupportedOperation(args.Operation) {
		return fail("fact_layer_query", fmt.Sprintf(
			"unknown operation %q; supported operations are: %s",
			args.Operation, strings.Join(trustirfacts.SupportedOperationStrings(), ", ")))
	}
	if h.Engine == nil {
		return fail("fact_layer_query", "fact layer engine not configured for this run")
	}
	if req.RunDir == "" || req.Repository == "" || req.Commit == "" {
		return fail("fact_layer_query", "run_dir/repository/commit not available for this run — the fact layer requires a pinned repository+commit")
	}

	fact, path, err := trustirfacts.RunAndPersist(ctx, h.Engine, trustirfacts.Request{
		RunDir:       req.RunDir,
		Repository:   req.Repository,
		Commit:       req.Commit,
		Operation:    trustirfacts.Operation(args.Operation),
		QueryPackDir: h.QueryPackDir,
		// The fact layer shells out to git to build the database's source
		// tree. Executor comes from the ActionRequest the planner already
		// populates, so the handler needs no field of its own; Bind stamps
		// this round's correlation ids on so a git-clone event deep inside
		// the fact layer is still attributable to the round that asked for
		// it. The CodeQL subprocesses are recorded by h.Engine, which
		// carries its own executor from the pipeline.
		//
		// Deliberately not marked ExecutorBacked: one fact_layer_query
		// action fans out to several subprocesses (git clone, git
		// checkout, codeql create, codeql analyze), so the action-level
		// event and the executor-level events are different granularities,
		// not duplicates.
		Exec: executor.Bind(req.Executor, executor.Binding{
			RunID: req.RunID, Agent: req.Agent, Round: req.Round,
		}),
	})
	if err != nil {
		return fail("fact_layer_query", fmt.Sprintf("fact layer call failed: %v", err))
	}

	out := factLayerQueryOutput{
		ToolFactRef:   path,
		Status:        fact.Status,
		Operation:     fact.Operation,
		LocationCount: len(fact.Locations),
		Locations:     fact.Locations,
		CoverageGaps:  fact.CoverageGaps,
		Error:         fact.Error,
	}
	if len(out.Locations) > factLayerQueryLocationCap {
		out.Locations = out.Locations[:factLayerQueryLocationCap]
		out.Truncated = true
	}

	data, merr := json.MarshalIndent(out, "", "  ")
	if merr != nil {
		return fail("fact_layer_query", fmt.Sprintf("marshal observation: %v", merr))
	}
	return ActionResult{Name: "fact_layer_query", OK: true, Output: string(data)}
}

var _ Handler = (*FactLayerQueryHandler)(nil)
