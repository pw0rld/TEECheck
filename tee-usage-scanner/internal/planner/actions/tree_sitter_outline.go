package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

type treeSitterOutlineArgs struct {
	Path string `json:"path"`
}

// TreeSitterOutlineHandler extracts a structural outline (functions and
// type declarations) from a source file using text heuristics
// (internal/planner/actions/langtext.go). Language-agnostic: any file
// isSourceFile recognizes is accepted; the historical action name is
// kept for prompt/schema stability.
type TreeSitterOutlineHandler struct{}

func (TreeSitterOutlineHandler) Name() string { return "tree_sitter_outline" }

func (TreeSitterOutlineHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args treeSitterOutlineArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("tree_sitter_outline", fmt.Sprintf("invalid args: %v", err))
	}
	if !isSourceFile(args.Path) {
		return fail("tree_sitter_outline", fmt.Sprintf("unsupported file type (got %s)", args.Path))
	}
	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}
	info, err := os.Stat(full)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}
	if info.IsDir() {
		return fail("tree_sitter_outline", fmt.Sprintf("%s is a directory", args.Path))
	}
	src, err := os.ReadFile(full)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}
	return ActionResult{Name: "tree_sitter_outline", OK: true, Output: textOutline(src)}
}
