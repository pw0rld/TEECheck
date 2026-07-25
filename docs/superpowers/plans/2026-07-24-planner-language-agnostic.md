# Language-Agnostic Planner (C/OP-TEE) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the L3 Planner language-agnostic so it can explore C/OP-TEE source, by replacing tree-sitter/`.rs` coupling with text heuristics and deleting the sink catalog.

**Architecture:** Option B′ — keep the source-exploration + path-tracing capabilities (`tree_sitter_outline`, `reverse_trace`) but reimplement their structural steps with text + signature heuristics (no grammar, no language registry). Delete the sink catalog entirely; guidance comes from the already-injected TWE/invariant/architecture prior knowledge. De-anchor the planner prompt.

**Tech Stack:** Go, `internal/planner` + `internal/planner/actions`, standard library `regexp`/`strings` (no new deps; the `smacker/go-tree-sitter` import is removed from the two actions).

## Global Constraints

- The planner core loop, anti-hallucination guards, CasePack generation, and review-chain wiring are NOT modified.
- `fact_layer_query` → `trustirfacts` (the fact layer) is NOT modified — its operation coverage is out of scope (#5/#6).
- Deletions are real deletions, not feature-flagged.
- `go test ./...` must be green at the end; teecheck-benchmark must be unaffected.
- Rust files must still work (`reverse_trace`/`tree_sitter_outline` on `.rs` must not error), accepting reduced precision vs the old tree-sitter path.
- The LLM-facing action name `tree_sitter_outline` is KEPT (renaming touches the prompt, schemas, and many tests for no functional gain).

---

## Task 1: Shared text heuristics helper

**Files:**
- Create: `tee-usage-scanner/internal/planner/actions/langtext.go`
- Test: `tee-usage-scanner/internal/planner/actions/langtext_test.go`

**Interfaces:**
- Produces:
  - `func isSourceFile(path string) bool`
  - `func functionSignatureLine(line string) (name string, ok bool)`
  - `func enclosingFunctionText(source []byte, targetLine int) string`
  - `func textOutline(source []byte) string`

- [ ] **Step 1: Write failing tests**

```go
package actions

import "testing"

func TestIsSourceFile(t *testing.T) {
	cases := map[string]bool{
		"a.rs": true, "b.c": true, "c.h": true, "d.cc": true, "e.cpp": true, "f.hpp": true,
		"Cargo.toml": false, "README.md": false, "x.txt": false, "dir/y.C": true,
	}
	for path, want := range cases {
		if got := isSourceFile(path); got != want {
			t.Errorf("isSourceFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFunctionSignatureLine(t *testing.T) {
	hit := map[string]string{
		"fn verify(&self) -> bool {":        "verify",
		"pub async unsafe fn go() {":        "go",
		"int foo(int x) {":                  "foo",
		"static void bar(void)":             "bar",
		"TEE_Result handle_invoke(uint32_t":  "handle_invoke",
	}
	for line, want := range hit {
		got, ok := functionSignatureLine(line)
		if !ok || got != want {
			t.Errorf("functionSignatureLine(%q) = (%q,%v), want (%q,true)", line, got, ok, want)
		}
	}
	miss := []string{
		"    return foo();", "if (x > 0) {", "while (running) {",
		"    bar();", "int x = baz(1);", "} ", "// fn comment(",
	}
	for _, line := range miss {
		if got, ok := functionSignatureLine(line); ok {
			t.Errorf("functionSignatureLine(%q) = (%q,true), want ok=false", line, got)
		}
	}
}

func TestEnclosingFunctionText(t *testing.T) {
	src := []byte(`void outer(int x)
{
    if (x) {
        target();
    }
}

void other() {
    noop();
}
`)
	// target() is on line 4, inside outer
	if got := enclosingFunctionText(src, 4); got != "outer" {
		t.Errorf("enclosing(line 4) = %q, want outer", got)
	}
	// a call between the two functions is top-level
	if got := enclosingFunctionText(src, 7); got != "<top-level>" {
		t.Errorf("enclosing(line 7) = %q, want <top-level>", got)
	}
}

func TestTextOutline(t *testing.T) {
	src := []byte("struct Foo {\n    int a;\n};\n\nint compute(int x) {\n    return x;\n}\n")
	out := textOutline(src)
	if !contains(out, "compute") || !contains(out, "line 5") {
		t.Errorf("outline missing compute@line5:\n%s", out)
	}
	if !contains(out, "Foo") || !contains(out, "line 1") {
		t.Errorf("outline missing Foo@line1:\n%s", out)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub { return true }
	}
	return false
})() }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run 'TestIsSourceFile|TestFunctionSignatureLine|TestEnclosingFunctionText|TestTextOutline' -v`
Expected: FAIL — `undefined: isSourceFile` etc.

- [ ] **Step 3: Write the helper**

```go
package actions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// sourceExtensions are the file types the planner's structural actions
// (tree_sitter_outline, reverse_trace) will parse. Language-agnostic:
// adding a language is adding an extension here, not a grammar.
var sourceExtensions = map[string]bool{
	".rs": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".hpp": true, ".cxx": true, ".hh": true,
}

func isSourceFile(path string) bool {
	return sourceExtensions[strings.ToLower(filepath.Ext(path))]
}

// rustFnRe / cFnRe recognize function-definition lines. cFnRe requires
// at least one leading type token and a "(" that does not end in ";"
// (a call or prototype), and the caller excludes control keywords.
var (
	rustFnRe = regexp.MustCompile(`^(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)`)
	cFnRe    = regexp.MustCompile(`^[A-Za-z_][\w\*\s]*?[\s\*]([A-Za-z_]\w*)\s*\(`)
	// structRe recognizes type-definition lines for the outline.
	structRe = regexp.MustCompile(`^(?:pub\s+)?(?:struct|enum|union|trait|impl)\s+([A-Za-z_]\w*)`)
	cStructRe = regexp.MustCompile(`^(?:typedef\s+)?struct\s+([A-Za-z_]\w*)`)
)

// cControlKeywords are words that look like a C function name but are
// control flow — they must never be reported as function signatures.
var cControlKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "return": true,
	"sizeof": true, "do": true, "else": true, "case": true,
}

func functionSignatureLine(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
		return "", false
	}
	if m := rustFnRe.FindStringSubmatch(t); m != nil {
		return m[1], true
	}
	// C: a definition line opens a body — it must contain "(" and must
	// not end in ";" (that would be a prototype or a call statement).
	if !strings.Contains(t, "(") || strings.HasSuffix(t, ";") {
		return "", false
	}
	if m := cFnRe.FindStringSubmatch(t); m != nil {
		name := m[1]
		// The token immediately before "name(" must not be a keyword,
		// and neither may `name` itself.
		if cControlKeywords[name] {
			return "", false
		}
		first := strings.Fields(t)
		if len(first) > 0 && cControlKeywords[first[0]] {
			return "", false
		}
		return name, true
	}
	return "", false
}

// enclosingFunctionText scans upward from targetLine (1-indexed) and
// returns the name of the nearest preceding function signature. A
// column-0 "}" encountered first means targetLine sits between
// top-level definitions, so it returns "<top-level>".
func enclosingFunctionText(source []byte, targetLine int) string {
	lines := strings.Split(string(source), "\n")
	if targetLine < 1 || targetLine > len(lines) {
		return "<top-level>"
	}
	for i := targetLine - 2; i >= 0; i-- {
		line := lines[i]
		if name, ok := functionSignatureLine(line); ok {
			return name
		}
		if len(line) > 0 && line[0] == '}' {
			return "<top-level>"
		}
	}
	return "<top-level>"
}

// textOutline emits one line per definition-looking line (functions and
// type declarations) with a 1-indexed line number and a truncated snippet.
func textOutline(source []byte) string {
	lines := strings.Split(string(source), "\n")
	var buf strings.Builder
	for i, line := range lines {
		t := strings.TrimSpace(line)
		var kind, name string
		if n, ok := functionSignatureLine(line); ok {
			kind, name = "function", n
		} else if m := structRe.FindStringSubmatch(t); m != nil {
			kind, name = "type", m[1]
		} else if m := cStructRe.FindStringSubmatch(t); m != nil {
			kind, name = "type", m[1]
		} else {
			continue
		}
		snippet := t
		if len(snippet) > 100 {
			snippet = snippet[:100] + "..."
		}
		fmt.Fprintf(&buf, "[%s %s] line %d: %s\n", kind, name, i+1, snippet)
	}
	return buf.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run 'TestIsSourceFile|TestFunctionSignatureLine|TestEnclosingFunctionText|TestTextOutline' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/actions/langtext.go tee-usage-scanner/internal/planner/actions/langtext_test.go
git commit -m "feat(planner): text heuristics for language-agnostic outline/trace"
```

---

## Task 2: Rework tree_sitter_outline to be language-agnostic

**Files:**
- Modify: `tee-usage-scanner/internal/planner/actions/tree_sitter_outline.go`
- Test: `tee-usage-scanner/internal/planner/actions/tree_sitter_outline_test.go`

**Interfaces:**
- Consumes: `isSourceFile`, `textOutline` (Task 1); existing `ResolvePath`, `fail`, `ActionResult`.
- Produces: unchanged handler name `tree_sitter_outline`.

- [ ] **Step 1: Write/adjust the failing test**

Add to `tree_sitter_outline_test.go`:

```go
func TestTreeSitterOutline_C(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ta.c")
	if err := os.WriteFile(path, []byte("TEE_Result handle_invoke(uint32_t cmd)\n{\n    return 0;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := TreeSitterOutlineHandler{}.Run(context.Background(), ActionRequest{RepoRoot: dir, Args: []byte(`{"path":"ta.c"}`)})
	if !res.OK {
		t.Fatalf("expected OK, got error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "handle_invoke") {
		t.Errorf("C outline missing handle_invoke:\n%s", res.Output)
	}
}

func TestTreeSitterOutline_RejectsNonSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.toml")
	_ = os.WriteFile(path, []byte("[package]\n"), 0o644)
	res := TreeSitterOutlineHandler{}.Run(context.Background(), ActionRequest{RepoRoot: dir, Args: []byte(`{"path":"Cargo.toml"}`)})
	if res.OK {
		t.Errorf("expected non-source file to be rejected")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestTreeSitterOutline_C -v`
Expected: FAIL — current code rejects `.c` with "only .rs files supported".

- [ ] **Step 3: Rewrite the handler**

Replace the entire body of `tree_sitter_outline.go` with (drops the `sitter`/`rust` imports and the tree-sitter walk):

```go
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
```

Delete any now-obsolete Rust-only test in `tree_sitter_outline_test.go` that asserts the exact old `[function_item] line X-Y:` format; keep/adjust tests that assert a `.rs` file still outlines (it will, via `textOutline`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestTreeSitterOutline -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/actions/tree_sitter_outline.go tee-usage-scanner/internal/planner/actions/tree_sitter_outline_test.go
git commit -m "refactor(planner): text-based outline, drop tree-sitter/.rs restriction"
```

---

## Task 3: Rework reverse_trace to be language-agnostic

**Files:**
- Modify: `tee-usage-scanner/internal/planner/actions/reverse_trace.go`
- Test: `tee-usage-scanner/internal/planner/actions/reverse_trace_test.go`

**Interfaces:**
- Consumes: `isSourceFile`, `functionSignatureLine`, `enclosingFunctionText` (Task 1).
- Produces: unchanged handler name `reverse_trace`, unchanged output format and caps.

- [ ] **Step 1: Write the failing test**

Add to `reverse_trace_test.go`:

```go
func TestReverseTrace_C(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "core.c"),
		[]byte("void verify(void) {}\n\nvoid caller(void)\n{\n    verify();\n}\n"), 0o644)
	res := ReverseTraceHandler{}.Run(context.Background(), ActionRequest{
		RepoRoot: dir, Args: []byte(`{"file":"core.c","symbol":"verify","depth":1}`),
	})
	if !res.OK {
		t.Fatalf("expected OK, got: %s", res.Error)
	}
	if !strings.Contains(res.Output, "caller") {
		t.Errorf("expected caller in trace:\n%s", res.Output)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestReverseTrace_C -v`
Expected: FAIL — current code rejects `.c` ("only .rs files supported").

- [ ] **Step 3: Apply the language-agnostic edits**

In `reverse_trace.go`:

1. Delete the imports `sitter "github.com/smacker/go-tree-sitter"` and `"github.com/smacker/go-tree-sitter/rust"`.

2. In `Run`, delete the `.rs` guard:
```go
	if !strings.HasSuffix(strings.ToLower(args.File), ".rs") {
		return fail("reverse_trace", fmt.Sprintf("only .rs files supported (got %s)", args.File))
	}
```
Replace with:
```go
	if !isSourceFile(args.File) {
		return fail("reverse_trace", fmt.Sprintf("unsupported file type (got %s)", args.File))
	}
```

3. In `findCallSites`, change the per-file filter from `.rs`-only to any source file:
```go
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
```
becomes:
```go
		if !isSourceFile(path) {
			return nil
		}
```

4. Replace the Rust-specific self-definition skip block (the `strings.HasPrefix(trimmed, "fn "+target)` ... chain) with a language-agnostic check using `functionSignatureLine`:
```go
			if name, ok := functionSignatureLine(line); ok && name == target {
				continue
			}
```

5. Replace the tree-sitter `findEnclosingFunction` call:
```go
			caller := findEnclosingFunction(data, uint32(i+1))
```
with:
```go
			caller := enclosingFunctionText(data, i+1)
```

6. Delete the now-unused functions `findEnclosingFunction` and `functionItemName` (the tree-sitter helpers) entirely from the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestReverseTrace -v`
Expected: PASS (including any pre-existing `.rs` reverse-trace test, which still works via text).

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/actions/reverse_trace.go tee-usage-scanner/internal/planner/actions/reverse_trace_test.go
git commit -m "refactor(planner): text-based reverse_trace, drop tree-sitter/.rs restriction"
```

---

## Task 4: Delete the sink catalog and rewire the registry

**Files:**
- Delete: `tee-usage-scanner/internal/planner/actions/sink_catalog_lookup.go`
- Delete: `tee-usage-scanner/internal/planner/actions/registry_with_sinks.go`
- Delete: `tee-usage-scanner/internal/planner/sinks/` (whole package — the catalog parser, now unused)
- Delete: `tee-usage-scanner/knowledge/sinks/rust.json` and `tee-usage-scanner/knowledge/sinks/README.md`
- Create: `tee-usage-scanner/internal/planner/actions/registry_with_nav.go`
- Modify: `tee-usage-scanner/internal/planner/actions/registry_with_facts.go`
- Modify: `tee-usage-scanner/internal/planner/actions/fact_layer_query.go` (comment only)
- Test: `tee-usage-scanner/internal/planner/actions/registry_test.go`

**Interfaces:**
- Produces:
  - `func NewDefaultRegistryWithNav() *Registry` — base + tree_sitter_outline, reverse_trace, done.
  - `func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string) *Registry` — NOTE new signature (no `catalogPath`).

- [ ] **Step 1: Write/adjust the failing test**

In `registry_test.go`, add:

```go
func TestNavRegistry_NoSinkAction(t *testing.T) {
	r := NewDefaultRegistryWithNav()
	names := r.Names()
	for _, n := range names {
		if n == "sink_catalog_lookup" {
			t.Fatalf("sink_catalog_lookup must not be registered")
		}
	}
	want := []string{"done", "list_dir", "read_file", "reverse_trace", "ripgrep", "tree_sitter_outline"}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w { found = true }
		}
		if !found {
			t.Errorf("expected action %q registered, got %v", w, names)
		}
	}
}
```
Remove any existing registry test that asserts `sink_catalog_lookup` is present or calls `NewDefaultRegistryWithSinks`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestNavRegistry -v`
Expected: FAIL — `undefined: NewDefaultRegistryWithNav`.

- [ ] **Step 3: Create the nav registry and delete sink files**

Create `registry_with_nav.go`:
```go
package actions

// NewDefaultRegistryWithNav returns the base read-only actions
// (list_dir, read_file, ripgrep) plus the language-agnostic navigation
// actions: tree_sitter_outline, reverse_trace, and the terminal done.
// The sink catalog is intentionally absent — guidance comes from the
// injected TWE/invariant/architecture prior knowledge, not a symbol list.
func NewDefaultRegistryWithNav() *Registry {
	r := NewDefaultRegistry()
	r.Register(TreeSitterOutlineHandler{})
	r.Register(ReverseTraceHandler{})
	r.Register(DoneHandler{})
	return r
}
```

Replace `registry_with_facts.go` body:
```go
package actions

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithNav with the
// fact_layer_query action: the Planner's entry point into the structured
// CodeQL/TrustIR fact layer. eng may be nil (facts off); the handler then
// fails closed per-call when fact_layer_query is invoked.
func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string) *Registry {
	r := NewDefaultRegistryWithNav()
	r.Register(&FactLayerQueryHandler{Engine: eng, QueryPackDir: queryPackDir})
	return r
}
```

Delete the files:
```bash
git rm tee-usage-scanner/internal/planner/actions/sink_catalog_lookup.go \
       tee-usage-scanner/internal/planner/actions/registry_with_sinks.go \
       tee-usage-scanner/knowledge/sinks/rust.json \
       tee-usage-scanner/knowledge/sinks/README.md
git rm -r tee-usage-scanner/internal/planner/sinks
```
Also delete `tee-usage-scanner/internal/planner/actions/sink_catalog_lookup_test.go` if present.

In `fact_layer_query.go`, update the stale comment near line 49 that references `SinkCatalogLookupHandler.CatalogPath's wiring convention` — reword to reference the handler's own `QueryPackDir` field instead (comment-only change, no behavior).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -v`
Expected: PASS (package compiles without the sink files; nav registry test green).

- [ ] **Step 5: Commit**

```bash
git add -A tee-usage-scanner/internal/planner/actions tee-usage-scanner/internal/planner/sinks tee-usage-scanner/knowledge/sinks
git commit -m "refactor(planner): delete sink catalog, add nav registry"
```

---

## Task 5: De-anchor the planner prompt

**Files:**
- Modify: `tee-usage-scanner/internal/planner/prompt.go`
- Test: `tee-usage-scanner/internal/planner/prompt_test.go`

**Interfaces:**
- Consumes: existing `BuildSystemPrompt(availableActions []string, obligationsBlock string, knowledge PriorKnowledge) string` (signature unchanged).

- [ ] **Step 1: Write the failing test**

Add to `prompt_test.go`:
```go
func TestBuildSystemPrompt_Deanchored(t *testing.T) {
	out := BuildSystemPrompt([]string{"ripgrep", "tree_sitter_outline", "done"}, "", PriorKnowledge{})
	for _, banned := range []string{"sink_catalog_lookup", `globs=["*.rs"]`, "Cargo", "*.rs"} {
		if strings.Contains(out, banned) {
			t.Errorf("system prompt still contains anchoring text %q", banned)
		}
	}
	for _, want := range []string{"invariant", "TWE"} {
		if !strings.Contains(out, want) {
			t.Errorf("system prompt missing guidance token %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/ -run TestBuildSystemPrompt_Deanchored -v`
Expected: FAIL — prompt still contains `sink_catalog_lookup`, `*.rs`, `Cargo`.

- [ ] **Step 3: Rewrite the APPROACH/HINTS and action schemas**

In `prompt.go`:

1. In `actionArgSchemas` (map around line 63): delete the `"sink_catalog_lookup": ...` entry; change the `tree_sitter_outline` and `reverse_trace` descriptions to drop ".rs" wording:
```go
	"tree_sitter_outline": `{"path": string (a source file: .c/.h/.rs/...)}`,
	"reverse_trace":       `{"file": string (a source file where the symbol is defined), "symbol": string (function name), "depth": int (1-3, default 1)} — walks backward through source files, returns a tree of who calls the symbol and who calls THOSE callers up to depth levels`,
```

2. Replace the APPROACH block (the numbered list starting `1. Start by querying sink_catalog_lookup ...`) with:
```go
	b.WriteString("APPROACH:\n")
	b.WriteString("  1. Start from the Project Invariants and TWE prior knowledge above: pick a security obligation this component must uphold.\n")
	b.WriteString("  2. Use ripgrep (with globs matching the project's source languages — see the `languages:` line in the round prompt) to find concrete sites related to that obligation.\n")
	b.WriteString("  3. Use tree_sitter_outline on a relevant source file to get its structure before reading specific ranges with read_file.\n")
	b.WriteString("  4. Use reverse_trace to walk backward from a trust-decision point to its callers.\n")
	b.WriteString("  5. When you have evidence, call done with candidates and, where a TWE/invariant applies, an investigations entry.\n\n")
```

3. Replace the HINTS lines that mention Cargo / `globs=["*.rs"]` / SGX-only dirs with language-neutral hints:
```go
	b.WriteString("HINTS:\n")
	b.WriteString("  - Match ripgrep globs to the target's source languages; skip lockfiles, build manifests, and docs.\n")
	b.WriteString("  - Prioritize directories that cross the trust boundary (TA entry points, secure-world core, attestation, key handling).\n")
```
(Adjust surrounding `b.WriteString` calls so the numbering/labels stay coherent; keep the RESPONSE FORMAT section untouched.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/ -run 'TestBuildSystemPrompt' -v`
Expected: PASS. Fix any pre-existing prompt test asserting the old sink-first wording by updating it to the new APPROACH.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/prompt.go tee-usage-scanner/internal/planner/prompt_test.go
git commit -m "refactor(planner): de-anchor prompt to TWE/invariant-driven, language-neutral"
```

---

## Task 6: Rewire runL3Planner (drop rust.json, use profile languages)

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (function `runL3Planner`, around lines 292-335)
- Test: `tee-usage-scanner/internal/pipeline/run_test.go` (existing end-to-end test must still pass)

**Interfaces:**
- Consumes: `actions.NewDefaultRegistryWithFacts(eng, queryPackDir)` (Task 4 new signature).

- [ ] **Step 1: Confirm the covering test exists**

The existing `internal/pipeline/run_test.go` runs the pipeline and asserts artifacts including the planner path. It is the regression guard here.

- [ ] **Step 2: Run it to see the current green baseline**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -v`
Expected: PASS (before edits). After the registry signature change in Task 4, this package will not compile until Step 3 — that is the failing state driving this task.

- [ ] **Step 3: Apply the edits in `runL3Planner`**

Delete the sink-catalog block:
```go
	catalogPath := filepath.Join(cfg.KnowledgeRoot, "sinks", "rust.json")
	if _, err := os.Stat(catalogPath); err != nil {
		return fmt.Errorf("sink catalog not found at %s: %w", catalogPath, err)
	}
```
Delete the `fmt.Printf("Catalog: %s\n", catalogPath)` line (keep the `Registered planner actions` print).
Change the registry construction:
```go
	registry := actions.NewDefaultRegistryWithFacts(catalogPath, eng, queryPackDir)
```
to:
```go
	registry := actions.NewDefaultRegistryWithFacts(eng, queryPackDir)
```
The `promptProfile` already sets `Languages: profile.Languages` (verified around line 348) — no change needed; the de-anchored prompt consumes it via the round prompt's `languages:` line.

Remove the now-unused `os` / `filepath` imports **only if** nothing else in the file uses them (check first; `run.go` almost certainly still uses both elsewhere — do not remove blindly).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ ./internal/planner/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/pipeline/run.go
git commit -m "refactor(pipeline): drop rust.json catalog wiring from L3 planner"
```

---

## Task 7: Full-suite verification and dead-code sweep

**Files:**
- Possibly modify: any test files elsewhere that referenced the deleted symbols.

- [ ] **Step 1: Build the whole module**

Run: `cd tee-usage-scanner && go build ./...`
Expected: success. If a `smacker/go-tree-sitter` import is now unused anywhere, `go build` fails — fix by removing the dead import.

- [ ] **Step 2: Vet**

Run: `cd tee-usage-scanner && go vet ./...`
Expected: no issues.

- [ ] **Step 3: Run the full test suite**

Run: `cd tee-usage-scanner && go test ./...`
Expected: all packages PASS. Fix any test still referencing `sink_catalog_lookup`, `NewDefaultRegistryWithSinks`, or the old outline format by updating it to the new behavior (these were surfaced by the blast-radius grep: planner tests, actions tests).

- [ ] **Step 4: Confirm benchmark is untouched**

Run: `cd teecheck-benchmark && go build ./...`
Expected: success (the benchmark evaluator does not depend on the planner internals; this confirms no accidental coupling).

- [ ] **Step 5: Tidy modules and commit**

```bash
cd tee-usage-scanner && go mod tidy
cd /root/pp_home/idea/TEECheck
git add -A
git commit -m "chore(planner): dead-code sweep + go mod tidy after sink/tree-sitter removal"
```

---

## Self-Review Notes (coverage vs spec)

- Spec §4 改 (reverse_trace text) → Task 3; (outline text) → Task 2; (prompt de-anchor + globs) → Task 5; (pipeline) → Task 6.
- Spec §4 删 (sink_catalog_lookup, registry_with_sinks, rust.json, prompt refs) → Task 4 + Task 5.
- Spec §5 language selection (profile.Languages, per-file dispatch) → Task 1 (`isSourceFile` per-file dispatch) + Task 6 (Languages already threaded).
- Spec §6 blast radius (twescan unaffected — verified; go-tree-sitter dep) → Task 7.
- Spec §8 acceptance 1-6 → Tasks 2/3 (C works), 5 (prompt), 4 (deletion), 3/2 (Rust still works), 7 (go test green, benchmark).
