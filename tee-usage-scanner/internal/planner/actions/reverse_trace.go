package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

// reverseTraceMaxDepth is the hard ceiling on BFS depth. depth > 3
// rarely provides audit value and risks combinatorial explosion on
// common utility symbols.
const reverseTraceMaxDepth = 3

// reverseTraceMaxCallersPerLevel caps how many callers we enumerate
// at each level. Without this a ubiquitous symbol like `Error` or
// `new` would return thousands of sites and blow the LLM's context.
const reverseTraceMaxCallersPerLevel = 30

// reverseTraceOutputCap caps the total output string size in bytes.
const reverseTraceOutputCap = 30000

type reverseTraceArgs struct {
	File   string `json:"file"`
	Symbol string `json:"symbol"`
	Depth  int    `json:"depth"`
}

// ReverseTraceHandler implements the reverse_trace action. Given a
// target file + symbol, it walks every .rs file in the repository,
// finds call sites of the symbol, uses tree-sitter to identify the
// enclosing function at each site, and recursively traces the
// enclosing functions as new targets — up to the requested depth.
//
// Output is a nested, indented tree suitable for LLM consumption:
//
//	verify_quote (target in attest/core/src/quote.rs)
//	  - attest/trusted/src/lib.rs:40 in Verifier::verify
//	    - peers/src/connection.rs:123 in attested_call
//	  - sgx/service/src/lib.rs:42 in sgx_verify_report
//
// This lets an LLM trace trust-decision points backward from a sink
// (e.g. "who calls verify_quote, and what's the surrounding context?")
// without having to issue dozens of ripgrep calls manually.
type ReverseTraceHandler struct{}

func (ReverseTraceHandler) Name() string { return "reverse_trace" }

func (ReverseTraceHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args reverseTraceArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("reverse_trace", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Symbol) == "" {
		return fail("reverse_trace", "symbol is required")
	}
	if !strings.HasSuffix(strings.ToLower(args.File), ".rs") {
		return fail("reverse_trace", fmt.Sprintf("only .rs files supported (got %s)", args.File))
	}
	full, err := ResolvePath(req.RepoRoot, args.File)
	if err != nil {
		return fail("reverse_trace", err.Error())
	}
	if _, err := os.Stat(full); err != nil {
		return fail("reverse_trace", err.Error())
	}

	depth := args.Depth
	if depth <= 0 {
		depth = 1
	}
	if depth > reverseTraceMaxDepth {
		depth = reverseTraceMaxDepth
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, "%s (target in %s)\n", args.Symbol, filepath.ToSlash(args.File))

	// Recurse via BFS. seen prevents cycles and duplicate work —
	// if we've already traced "Verifier::verify" at depth 1, we
	// don't retrace it at depth 2 even if it's reached via another
	// path.
	seen := map[string]bool{args.Symbol: true}
	totalCallers := traceLevel(ctx, req.RepoRoot, args.Symbol, depth, 0, seen, &buf)
	if totalCallers == 0 {
		buf.WriteString("  (no callers found)\n")
	}

	output := buf.String()
	truncated := false
	if len(output) > reverseTraceOutputCap {
		output = output[:reverseTraceOutputCap] + "\n... (truncated)"
		truncated = true
	}
	return ActionResult{
		Name:      "reverse_trace",
		OK:        true,
		Output:    output,
		Truncated: truncated,
	}
}

// traceLevel finds callers of `target` across the repo, emits one
// line per call site into buf, and recurses on each caller until
// remaining=0. Returns the total number of call sites emitted at or
// below this level.
func traceLevel(ctx context.Context, repoRoot, target string, remaining, level int, seen map[string]bool, buf *strings.Builder) int {
	if remaining <= 0 {
		return 0
	}
	select {
	case <-ctx.Done():
		return 0
	default:
	}

	callers := findCallSites(ctx, repoRoot, target)
	if len(callers) > reverseTraceMaxCallersPerLevel {
		callers = callers[:reverseTraceMaxCallersPerLevel]
	}

	indent := strings.Repeat("  ", level+1)
	total := 0
	for _, cs := range callers {
		if seen[cs.Caller] {
			continue
		}
		seen[cs.Caller] = true
		fmt.Fprintf(buf, "%s- %s:%d in %s\n", indent, cs.File, cs.Line, cs.Caller)
		total++
		// Recurse on the caller symbol
		total += traceLevel(ctx, repoRoot, cs.Caller, remaining-1, level+1, seen, buf)
	}
	return total
}

// callSite is a single occurrence of `target(` inside an enclosing
// function somewhere in the repo.
type callSite struct {
	File   string // repo-relative
	Line   int    // 1-indexed
	Caller string // enclosing function name, or "<top-level>" if none
}

// findCallSites walks every .rs file in repoRoot and returns every
// line that textually calls `target(`. For each hit it uses
// tree-sitter to identify the enclosing function_item.
//
// This is deliberately text-first: we grep for the symbol as a
// substring (with a "(" suffix to avoid matching `target_other`), then
// confirm via tree-sitter that the containing scope is a function.
// A fully semantic resolver would require full name resolution across
// crates — future work.
func findCallSites(ctx context.Context, repoRoot, target string) []callSite {
	var sites []callSite
	needle := target + "("
	_ = filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if info.IsDir() {
			// Skip common noise dirs for performance.
			name := info.Name()
			if name == "target" || name == ".git" || name == "node_modules" || name == ".cargo" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !strings.Contains(string(data), needle) {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		// Find each line containing the needle.
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !strings.Contains(line, needle) {
				continue
			}
			// Avoid matching the function's own definition
			// ("fn target(...)"). If the line looks like a
			// declaration rather than a call, skip it.
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "fn "+target) ||
				strings.HasPrefix(trimmed, "pub fn "+target) ||
				strings.HasPrefix(trimmed, "async fn "+target) ||
				strings.HasPrefix(trimmed, "pub async fn "+target) ||
				strings.HasPrefix(trimmed, "unsafe fn "+target) ||
				strings.HasPrefix(trimmed, "pub unsafe fn "+target) {
				continue
			}
			caller := findEnclosingFunction(data, uint32(i+1))
			sites = append(sites, callSite{
				File:   rel,
				Line:   i + 1,
				Caller: caller,
			})
		}
		return nil
	})
	return sites
}

// findEnclosingFunction parses the source with tree-sitter and
// returns the name of the innermost function_item / impl method
// whose line range contains targetLine (1-indexed). Returns
// "<top-level>" if no enclosing function is found (e.g. the call
// is in a static initializer or module body).
func findEnclosingFunction(source []byte, targetLine uint32) string {
	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil || tree == nil {
		return "<top-level>"
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return "<top-level>"
	}
	// Walk DFS, tracking the deepest function_item node that
	// contains targetLine.
	best := ""
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		startLine := n.StartPoint().Row + 1
		endLine := n.EndPoint().Row + 1
		if targetLine < startLine || targetLine > endLine {
			return
		}
		if n.Type() == "function_item" {
			name := functionItemName(n, source)
			if name != "" {
				best = name
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(root)
	if best == "" {
		return "<top-level>"
	}
	return best
}

// functionItemName returns the name identifier of a function_item
// tree-sitter node, or "" if none found.
func functionItemName(fn *sitter.Node, source []byte) string {
	for i := 0; i < int(fn.ChildCount()); i++ {
		child := fn.Child(i)
		if child.Type() == "identifier" {
			return string(source[child.StartByte():child.EndByte()])
		}
	}
	return ""
}
