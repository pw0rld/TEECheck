package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// factLayerQueryLocationCap bounds how many locations the compact
// observation echoes verbatim. A single fact-layer query result is
// typically a handful of flagged sites; this cap exists only to guard
// against a pathological result blowing up the round prompt — the full
// list always lives in the persisted ToolFact (ToolFactRef).
const factLayerQueryLocationCap = 20

// factLayerQueryFindingCap and factLayerQueryRelatedCap bound the same way
// for findings. A thin-shell query emits one finding per flagged site with a
// handful of named sites each; the caps only guard the pathological case.
const (
	factLayerQueryFindingCap = 10
	factLayerQueryRelatedCap = 10
)

type factLayerQueryArgs struct {
	Operation string `json:"operation"`
}

// factLayerQueryOutput is the compact observation the LLM sees back for a
// fact_layer_query call. It intentionally excludes the raw ToolFact.Result
// blob — §11.2/§24: "观察结果使用 artifact refs", not the full tool payload
// re-entering the prompt. Full detail is always available at ToolFactRef.
//
// Findings is NOT part of that excluded payload, and leaving it out was a
// defect. A thin-shell query's whole answer lives in the finding message and
// the sites it names: RollbackVersionNotPropagated resolves "producer $@
// never propagates rollback field '<f>'; authority $@ therefore checks a
// default version" to real symbols and lines, and the authority is in a
// DIFFERENT FILE from the primary location. Every downstream agent already
// sees all of it through artifacts.FormatToolFact; only the Planner — the
// one stage that decides what to investigate next — got a projection with
// those fields stripped.
//
// On CVE-2026-44362 that cost the run the finding. The fact layer resolved
// the authority to core/kernel/ree_fs_ta.c:314/:639 check_update_version and
// persisted it; the Planner's observation showed only
// core/crypto/signed_hdr.c:262. Not knowing a caller had already been found,
// it ran reverse_trace over a single-file fixture, got "(no callers found)",
// and wrote that into counterevidence — from which the Challenger concluded
// the whole path was dead code. See docs/bugs/BUG-002 §3.4.
type factLayerQueryOutput struct {
	ToolFactRef   string                   `json:"tool_fact_ref"`
	Status        string                   `json:"status"`
	Operation     string                   `json:"operation"`
	LocationCount int                      `json:"location_count"`
	Locations     []artifacts.ToolLocation `json:"locations,omitempty"`
	Findings      []artifacts.ToolFinding  `json:"findings,omitempty"`
	Truncated     bool                     `json:"truncated,omitempty"`
	CoverageGaps  []string                 `json:"coverage_gaps,omitempty"`
	Error         string                   `json:"error,omitempty"`
}

// capFindings bounds the findings echoed into a round prompt without
// touching a message's text. A message IS the query's conclusion, so
// truncating one mid-sentence would leave the model a half-stated fact —
// worse than the honest signal that the list was cut, which Truncated
// carries.
func capFindings(findings []artifacts.ToolFinding) ([]artifacts.ToolFinding, bool) {
	truncated := false
	if len(findings) > factLayerQueryFindingCap {
		findings = findings[:factLayerQueryFindingCap]
		truncated = true
	}
	out := make([]artifacts.ToolFinding, 0, len(findings))
	for _, f := range findings {
		if len(f.Related) > factLayerQueryRelatedCap {
			f.Related = f.Related[:factLayerQueryRelatedCap]
			truncated = true
		}
		out = append(out, f)
	}
	return out, truncated
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
	Engine trustirfacts.Engine
	// DB owns the run's CodeQL database. It is the same value the program
	// index stage holds, so a planner round that needs a fact finds the
	// database already built rather than building a second one.
	DB           codedb.DatabaseProvider
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

	// Deliberately not marked ExecutorBacked: one fact_layer_query action
	// fans out to several subprocesses (codeql create, codeql analyze), so
	// the action-level event and the executor-level events are different
	// granularities, not duplicates.
	//
	// The git clone that used to happen here is gone: internal/codedb owns
	// the checkout, and the pipeline acquires it before the first stage, so
	// by the time a planner round asks for a fact the tree is already there.
	fact, path, err := trustirfacts.RunAndPersist(ctx, h.Engine, h.DB, trustirfacts.Request{
		RunDir:       req.RunDir,
		Repository:   req.Repository,
		Commit:       req.Commit,
		Operation:    trustirfacts.Operation(args.Operation),
		QueryPackDir: h.QueryPackDir,
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
	findings, findingsTruncated := capFindings(fact.Findings)
	out.Findings = findings
	out.Truncated = out.Truncated || findingsTruncated

	data, merr := json.MarshalIndent(out, "", "  ")
	if merr != nil {
		return fail("fact_layer_query", fmt.Sprintf("marshal observation: %v", merr))
	}
	return ActionResult{Name: "fact_layer_query", OK: true, Output: string(data)}
}

var _ Handler = (*FactLayerQueryHandler)(nil)
