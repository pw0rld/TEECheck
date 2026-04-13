package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

type treeSitterOutlineArgs struct {
	Path string `json:"path"`
}

// TreeSitterOutlineHandler extracts a structural outline (functions,
// structs, impls, use declarations, extern blocks) from a Rust source
// file using tree-sitter. Output is one line per top-level item with
// the node type, line number, and a truncated snippet.
//
// The action accepts only files with a `.rs` extension. Non-Rust files
// return an error so the LLM can fall back to read_file or ripgrep.
type TreeSitterOutlineHandler struct{}

func (TreeSitterOutlineHandler) Name() string { return "tree_sitter_outline" }

func (TreeSitterOutlineHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args treeSitterOutlineArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("tree_sitter_outline", fmt.Sprintf("invalid args: %v", err))
	}
	if !strings.HasSuffix(strings.ToLower(args.Path), ".rs") {
		return fail("tree_sitter_outline", fmt.Sprintf("only .rs files supported (got %s)", args.Path))
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

	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	tree, err := parser.ParseCtx(ctx, nil, src)
	if err != nil {
		return fail("tree_sitter_outline", fmt.Sprintf("tree-sitter parse: %v", err))
	}
	defer tree.Close()

	var buf strings.Builder
	root := tree.RootNode()
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		emitOutlineNode(child, src, &buf)
	}

	return ActionResult{
		Name:   "tree_sitter_outline",
		OK:     true,
		Output: buf.String(),
	}
}

// outlineNodeKinds is the set of top-level Rust node types we surface
// in the outline. Other node types (comments, attribute_item alone,
// macros) are skipped because they would clutter the LLM's view.
var outlineNodeKinds = map[string]bool{
	"function_item":    true,
	"struct_item":      true,
	"enum_item":        true,
	"impl_item":        true,
	"trait_item":       true,
	"foreign_mod_item": true,
	"use_declaration":  true,
	"mod_item":         true,
	"const_item":       true,
	"static_item":      true,
	"type_item":        true,
}

func emitOutlineNode(node *sitter.Node, src []byte, buf *strings.Builder) {
	t := node.Type()
	if !outlineNodeKinds[t] {
		return
	}
	startLine := node.StartPoint().Row + 1
	endLine := node.EndPoint().Row + 1
	snippet := nodeSnippet(node, src)
	fmt.Fprintf(buf, "[%s] line %d-%d: %s\n", t, startLine, endLine, snippet)

	// For impl blocks, also surface inner functions one level deep.
	if t == "impl_item" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "declaration_list" {
				for j := 0; j < int(ch.ChildCount()); j++ {
					inner := ch.Child(j)
					if inner.Type() == "function_item" {
						innerStart := inner.StartPoint().Row + 1
						innerEnd := inner.EndPoint().Row + 1
						innerSnippet := nodeSnippet(inner, src)
						fmt.Fprintf(buf, "  [function_item] line %d-%d: %s\n", innerStart, innerEnd, innerSnippet)
					}
				}
			}
		}
	}
}

// nodeSnippet returns the first line of a node's source text, truncated
// to 100 chars.
func nodeSnippet(node *sitter.Node, src []byte) string {
	text := string(src[node.StartByte():node.EndByte()])
	lines := strings.SplitN(text, "\n", 2)
	first := strings.TrimSpace(lines[0])
	if len(first) > 100 {
		first = first[:100] + "..."
	}
	return first
}
