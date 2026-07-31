package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomix"
)

const repomixOutputCap = 50000

type repomixSummarizeArgs struct {
	Path     string `json:"path"`
	Compress bool   `json:"compress"`
}

// RepomixSummarizeHandler wraps internal/repomix.Pack into a planner
// action. The LLM can request a compressed view of a subtree to
// orient itself before drilling in with read_file or
// tree_sitter_outline.
//
// repomix shells out to `npx repomix`, which requires Node.js and
// npx in PATH. If unavailable, the action returns OK=false with a
// clear error so the LLM can fall back.
//
// Output is capped at repomixOutputCap bytes (50KB) to prevent the
// LLM context from being blown by a massive monorepo summary.
type RepomixSummarizeHandler struct{}

func (RepomixSummarizeHandler) Name() string { return "repomix_summarize" }

func (RepomixSummarizeHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args repomixSummarizeArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("repomix_summarize", fmt.Sprintf("invalid args: %v", err))
	}
	if !repomix.Available() {
		return fail("repomix_summarize", "npx (required by repomix) not installed")
	}

	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("repomix_summarize", err.Error())
	}

	// The executor comes from the ActionRequest the planner already
	// populates for every call, so this handler needs no field of its own —
	// the same seam RipgrepHandler uses. Unlike ripgrep it does NOT refuse
	// a nil executor: repomix must keep working for callers with no event
	// stream, and repomix.Pack falls back to a silent local executor.
	//
	// Deliberately not marked ExecutorBacked: the planner's own
	// tool_call_* pair for this action carries the FORMATTED, capped
	// observation the LLM actually saw, while the executor's pair carries
	// the raw npx invocation. They describe different things at different
	// granularities, so suppressing either would lose information rather
	// than remove a duplicate.
	result, err := repomix.Pack(ctx, repomix.PackRequest{
		RepoRoot: full,
		Compress: args.Compress,
		Exec: executor.Bind(req.Executor, executor.Binding{
			RunID: req.RunID, Agent: req.Agent, Round: req.Round,
		}),
	})
	if err != nil {
		return fail("repomix_summarize", fmt.Sprintf("repomix: %v", err))
	}

	output := repomix.FormatForPrompt(result, repomixOutputCap)
	truncated := len(output) >= repomixOutputCap
	return ActionResult{
		Name:      "repomix_summarize",
		OK:        true,
		Output:    output,
		Truncated: truncated,
	}
}
