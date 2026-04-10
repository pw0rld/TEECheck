# Three-Agent Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 6-stage serial pipeline with a 3-agent architecture (Scanner/Reviewer/Auditor) driven by `teecheck run <url-or-path>`, with automatic repo cloning and AI-driven code graph generation.

**Architecture:** Three new packages: `repofetch` (clone/detect repos), `scanner` (graph generation with pluggable adapters), `pipeline` (3-agent orchestration). All existing stage implementations (preprocessor, mapper, expert, etc.) are reused internally. A new `teecheck run` command wraps everything into a single entry point.

**Tech Stack:** Go 1.25, stdlib + os/exec for git clone, existing internal packages.

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `internal/repofetch/fetch.go` | URL/path detection, git clone, commit extraction |
| `internal/repofetch/fetch_test.go` | Tests for fetch logic |
| `internal/scanner/graph_adapter.go` | GraphAdapter interface, GraphRequest/Result/Node/Edge types |
| `internal/scanner/registry.go` | GraphRegistry: register, run, merge |
| `internal/scanner/registry_test.go` | Tests for registry and merge |
| `internal/scanner/merge.go` | Graph dedup/merge logic |
| `internal/scanner/regex/adapter.go` | Regex-based graph extraction |
| `internal/scanner/regex/langs.go` | Per-language regex rules |
| `internal/scanner/regex/adapter_test.go` | Tests for regex adapter |
| `internal/scanner/semgrep/adapter.go` | Semgrep graph adapter (Available() checks binary) |
| `internal/scanner/codeql/adapter.go` | Stub |
| `internal/scanner/joern/adapter.go` | Stub |
| `internal/scanner/scan.go` | Orchestrate graph generation (heuristic + LLM) |
| `internal/scanner/scan_test.go` | Tests for scan orchestration |
| `internal/pipeline/run.go` | 3-agent pipeline entry point |
| `internal/pipeline/run_test.go` | Integration test |

### Modified Files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `Target`, `Mode` fields; add `parseRun` |
| `internal/runfs/paths.go` | Add new directory path helpers |
| `cmd/teecheck/main.go` | Add `"run"` command routing |

---

## Task 1: Repo Fetch

**Files:**
- Create: `internal/repofetch/fetch.go`
- Create: `internal/repofetch/fetch_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/repofetch/fetch_test.go
package repofetch_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
)

func TestFetchLocalPath(t *testing.T) {
	// Create a fake git repo
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "init")

	result, err := repofetch.Fetch(dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if result.LocalPath != dir {
		t.Fatalf("expected local path %s, got %s", dir, result.LocalPath)
	}
	if result.Commit == "" {
		t.Fatal("expected non-empty commit")
	}
	if result.RepoURL != "" {
		t.Fatalf("expected empty repo URL for local path, got %s", result.RepoURL)
	}
	if result.Cloned {
		t.Fatal("expected Cloned=false for local path")
	}
}

func TestFetchDetectsURL(t *testing.T) {
	if _, err := repofetch.Fetch("https://github.com/example/repo.git"); err == nil {
		// Clone will fail (fake URL) but it should attempt it
		// We just verify it doesn't treat a URL as a local path
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo", true},
		{"http://example.com/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"/home/user/repo", false},
		{"./relative/path", false},
		{"repo-name", false},
	}
	for _, tt := range tests {
		got := repofetch.IsURL(tt.input)
		if got != tt.want {
			t.Errorf("IsURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := append([]string{"-C", dir}, args...)
	out, err := execCommand("git", cmd...)
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func execCommand(name string, args ...string) ([]byte, error) {
	import_exec := __import__("os/exec")
	_ = import_exec
	// Actually use os/exec inline
	return nil, nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
```

Actually, let me write the correct test without the broken helper:

```go
// internal/repofetch/fetch_test.go
package repofetch_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
)

func TestFetchLocalPath(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init")
	git(t, dir, "config", "user.email", "test@test.com")
	git(t, dir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "init")

	result, err := repofetch.Fetch(dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if result.LocalPath != dir {
		t.Fatalf("expected local path %s, got %s", dir, result.LocalPath)
	}
	if result.Commit == "" {
		t.Fatal("expected non-empty commit")
	}
	if result.Cloned {
		t.Fatal("expected Cloned=false for local path")
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo", true},
		{"http://example.com/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"/home/user/repo", false},
		{"./relative/path", false},
		{"repo-name", false},
	}
	for _, tt := range tests {
		got := repofetch.IsURL(tt.input)
		if got != tt.want {
			t.Errorf("IsURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/repofetch/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Write the implementation**

```go
// internal/repofetch/fetch.go
package repofetch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FetchResult struct {
	LocalPath string
	Commit    string
	RepoURL   string
	Cloned    bool
}

func Fetch(target string) (FetchResult, error) {
	if IsURL(target) {
		return cloneRepo(target)
	}
	return fetchLocal(target)
}

func IsURL(s string) bool {
	return strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git@")
}

func cloneRepo(url string) (FetchResult, error) {
	dir, err := os.MkdirTemp("", "teecheck-clone-*")
	if err != nil {
		return FetchResult{}, fmt.Errorf("create temp dir: %w", err)
	}

	cmd := exec.Command("git", "clone", "--depth", "50", url, dir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return FetchResult{}, fmt.Errorf("git clone %s: %w", url, err)
	}

	commit, err := getHeadCommit(dir)
	if err != nil {
		os.RemoveAll(dir)
		return FetchResult{}, err
	}

	return FetchResult{
		LocalPath: dir,
		Commit:    commit,
		RepoURL:   url,
		Cloned:    true,
	}, nil
}

func fetchLocal(path string) (FetchResult, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FetchResult{}, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return FetchResult{}, fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return FetchResult{}, fmt.Errorf("%s is not a directory", abs)
	}

	commit, err := getHeadCommit(abs)
	if err != nil {
		commit = "unknown"
	}

	// Try to get remote URL
	var repoURL string
	out, err := exec.Command("git", "-C", abs, "remote", "get-url", "origin").Output()
	if err == nil {
		repoURL = strings.TrimSpace(string(out))
	}

	return FetchResult{
		LocalPath: abs,
		Commit:    commit,
		RepoURL:   repoURL,
		Cloned:    false,
	}, nil
}

func getHeadCommit(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD in %s: %w", dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/repofetch/ -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/repofetch/
git commit -m "feat(repofetch): add repo URL/path detection and cloning"
```

---

## Task 2: Graph Adapter Types

**Files:**
- Create: `internal/scanner/graph_adapter.go`

- [ ] **Step 1: Create the types file**

```go
// internal/scanner/graph_adapter.go
package scanner

import "context"

type GraphNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Language string `json:"language"`
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type GraphResult struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type GraphRequest struct {
	RepoRoot  string
	Languages []string
	Focus     string
}

type GraphAdapter interface {
	Name() string
	Available() bool
	ExtractGraph(ctx context.Context, req GraphRequest) (GraphResult, error)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/scanner/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/graph_adapter.go
git commit -m "feat(scanner): add GraphAdapter interface and graph types"
```

---

## Task 3: Graph Merge Logic

**Files:**
- Create: `internal/scanner/merge.go`
- Create: `internal/scanner/registry.go`
- Create: `internal/scanner/registry_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/registry_test.go
package scanner_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type fakeGraphAdapter struct {
	name      string
	available bool
	result    scanner.GraphResult
}

func (f *fakeGraphAdapter) Name() string      { return f.name }
func (f *fakeGraphAdapter) Available() bool    { return f.available }
func (f *fakeGraphAdapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return f.result, nil
}

func TestGraphRegistryRunAllMerges(t *testing.T) {
	reg := scanner.NewGraphRegistry()
	reg.Register(&fakeGraphAdapter{
		name: "tool-a", available: true,
		result: scanner.GraphResult{
			Nodes: []scanner.GraphNode{
				{ID: "file-main", Kind: "file", Name: "main.rs", Path: "src/main.rs", Language: "rust"},
				{ID: "sym-foo", Kind: "function", Name: "foo", Path: "src/main.rs", Language: "rust"},
			},
			Edges: []scanner.GraphEdge{
				{Source: "file-main", Target: "sym-foo", Kind: "defines"},
			},
		},
	})
	reg.Register(&fakeGraphAdapter{
		name: "tool-b", available: true,
		result: scanner.GraphResult{
			Nodes: []scanner.GraphNode{
				{ID: "file-main", Kind: "file", Name: "main.rs", Path: "src/main.rs", Language: "rust"},
				{ID: "sym-bar", Kind: "function", Name: "bar", Path: "src/lib.rs", Language: "rust"},
			},
			Edges: []scanner.GraphEdge{
				{Source: "sym-foo", Target: "sym-bar", Kind: "calls"},
			},
		},
	})
	reg.Register(&fakeGraphAdapter{name: "tool-c", available: false})

	result, err := reg.RunAll(context.Background(), scanner.GraphRequest{RepoRoot: "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have 3 unique nodes (file-main deduped)
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d: %+v", len(result.Nodes), result.Nodes)
	}
	// Should have 2 unique edges
	if len(result.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %+v", len(result.Edges), result.Edges)
	}
}

func TestGraphRegistryAvailable(t *testing.T) {
	reg := scanner.NewGraphRegistry()
	reg.Register(&fakeGraphAdapter{name: "yes", available: true})
	reg.Register(&fakeGraphAdapter{name: "no", available: false})

	avail := reg.Available()
	if len(avail) != 1 || avail[0] != "yes" {
		t.Fatalf("expected [yes], got %v", avail)
	}
}

func TestMergeGraphResults(t *testing.T) {
	a := scanner.GraphResult{
		Nodes: []scanner.GraphNode{{ID: "n1", Kind: "file", Name: "a"}, {ID: "n2", Kind: "function", Name: "b"}},
		Edges: []scanner.GraphEdge{{Source: "n1", Target: "n2", Kind: "defines"}},
	}
	b := scanner.GraphResult{
		Nodes: []scanner.GraphNode{{ID: "n1", Kind: "file", Name: "a"}, {ID: "n3", Kind: "function", Name: "c"}},
		Edges: []scanner.GraphEdge{{Source: "n1", Target: "n2", Kind: "defines"}, {Source: "n2", Target: "n3", Kind: "calls"}},
	}
	merged := scanner.MergeGraphResults(a, b)
	if len(merged.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(merged.Nodes))
	}
	if len(merged.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(merged.Edges))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/ -v`
Expected: FAIL

- [ ] **Step 3: Write merge.go**

```go
// internal/scanner/merge.go
package scanner

type nodeKey struct {
	ID string
}

type edgeKey struct {
	Source string
	Target string
	Kind   string
}

func MergeGraphResults(results ...GraphResult) GraphResult {
	seenNodes := make(map[string]bool)
	seenEdges := make(map[edgeKey]bool)
	var merged GraphResult

	for _, r := range results {
		for _, n := range r.Nodes {
			if !seenNodes[n.ID] {
				seenNodes[n.ID] = true
				merged.Nodes = append(merged.Nodes, n)
			}
		}
		for _, e := range r.Edges {
			key := edgeKey{Source: e.Source, Target: e.Target, Kind: e.Kind}
			if !seenEdges[key] {
				seenEdges[key] = true
				merged.Edges = append(merged.Edges, e)
			}
		}
	}
	return merged
}
```

- [ ] **Step 4: Write registry.go**

```go
// internal/scanner/registry.go
package scanner

import (
	"context"
	"fmt"
	"sort"
)

type GraphRegistry struct {
	adapters map[string]GraphAdapter
	order    []string
}

func NewGraphRegistry() *GraphRegistry {
	return &GraphRegistry{adapters: make(map[string]GraphAdapter)}
}

func (r *GraphRegistry) Register(a GraphAdapter) {
	name := a.Name()
	if _, exists := r.adapters[name]; !exists {
		r.order = append(r.order, name)
	}
	r.adapters[name] = a
}

func (r *GraphRegistry) Get(name string) (GraphAdapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

func (r *GraphRegistry) Available() []string {
	var names []string
	for _, name := range r.order {
		if r.adapters[name].Available() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *GraphRegistry) RunAll(ctx context.Context, req GraphRequest) (GraphResult, error) {
	var results []GraphResult
	for _, name := range r.order {
		a := r.adapters[name]
		if !a.Available() {
			continue
		}
		result, err := a.ExtractGraph(ctx, req)
		if err != nil {
			return GraphResult{}, fmt.Errorf("graph adapter %s: %w", name, err)
		}
		results = append(results, result)
	}
	return MergeGraphResults(results...), nil
}

func (r *GraphRegistry) RunByName(ctx context.Context, name string, req GraphRequest) (GraphResult, error) {
	a, ok := r.adapters[name]
	if !ok {
		return GraphResult{}, fmt.Errorf("unknown graph adapter: %s", name)
	}
	if !a.Available() {
		return GraphResult{}, fmt.Errorf("graph adapter %s is not available", name)
	}
	return a.ExtractGraph(ctx, req)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/ -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/merge.go internal/scanner/registry.go internal/scanner/registry_test.go
git commit -m "feat(scanner): add GraphRegistry and merge logic"
```

---

## Task 4: Regex Graph Adapter + Language Rules

**Files:**
- Create: `internal/scanner/regex/langs.go`
- Create: `internal/scanner/regex/adapter.go`
- Create: `internal/scanner/regex/adapter_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/regex/adapter_test.go
package regex_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/regex"
)

func TestRegexAdapterRust(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "verify.rs"), []byte(`
pub fn verify_quote(report: &Report) -> Result<(), Error> {
    verify_qe_identity_policy(report)?;
    Ok(())
}

fn verify_qe_identity_policy(report: &Report) -> Result<(), Error> {
    // TODO check freshness
    Ok(())
}

pub struct AttestationReport {
    pub quote: Vec<u8>,
}
`), 0o644)

	a := regex.New()
	if a.Name() != "regex" {
		t.Fatalf("expected name regex, got %s", a.Name())
	}
	if !a.Available() {
		t.Fatal("expected regex to be available")
	}

	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have: 1 file node + 3 symbol nodes (2 functions + 1 struct)
	fileNodes := 0
	funcNodes := 0
	structNodes := 0
	for _, n := range result.Nodes {
		switch n.Kind {
		case "file":
			fileNodes++
		case "function":
			funcNodes++
		case "struct":
			structNodes++
		}
	}
	if fileNodes != 1 {
		t.Fatalf("expected 1 file node, got %d", fileNodes)
	}
	if funcNodes != 2 {
		t.Fatalf("expected 2 function nodes, got %d", funcNodes)
	}
	if structNodes != 1 {
		t.Fatalf("expected 1 struct node, got %d", structNodes)
	}

	// Should have defines edges
	definesCount := 0
	for _, e := range result.Edges {
		if e.Kind == "defines" {
			definesCount++
		}
	}
	if definesCount < 3 {
		t.Fatalf("expected at least 3 defines edges, got %d", definesCount)
	}
}

func TestRegexAdapterGo(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`
package main

func HandleRequest(w http.ResponseWriter, r *http.Request) {
    processData(r.Body)
}

func processData(data io.Reader) error {
    return nil
}

type Server struct {
    addr string
}
`), 0o644)

	a := regex.New()
	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	funcNodes := 0
	structNodes := 0
	for _, n := range result.Nodes {
		switch n.Kind {
		case "function":
			funcNodes++
		case "struct":
			structNodes++
		}
	}
	if funcNodes != 2 {
		t.Fatalf("expected 2 function nodes, got %d", funcNodes)
	}
	if structNodes != 1 {
		t.Fatalf("expected 1 struct node, got %d", structNodes)
	}
}

func TestRegexAdapterSkipsDirs(t *testing.T) {
	dir := t.TempDir()
	// Create a node_modules dir that should be skipped
	nm := filepath.Join(dir, "node_modules", "dep")
	os.MkdirAll(nm, 0o755)
	os.WriteFile(filepath.Join(nm, "index.ts"), []byte("export function ignored() {}\n"), 0o644)
	// Create a real file
	os.WriteFile(filepath.Join(dir, "app.ts"), []byte("export function real() {}\n"), 0o644)

	a := regex.New()
	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, n := range result.Nodes {
		if n.Name == "ignored" {
			t.Fatal("should have skipped node_modules")
		}
	}
}

// Compile-time interface check
var _ scanner.GraphAdapter = (*regex.Adapter)(nil)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/regex/ -v`
Expected: FAIL

- [ ] **Step 3: Write langs.go**

```go
// internal/scanner/regex/langs.go
package regex

import "regexp"

type LangRule struct {
	Name       string
	Extensions []string
	FuncDef    *regexp.Regexp
	StructDef  *regexp.Regexp
}

var defaultLangs = []LangRule{
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		FuncDef:    regexp.MustCompile(`(?:pub\s+)?(?:async\s+)?fn\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:pub\s+)?(?:struct|trait|enum)\s+(\w+)`),
	},
	{
		Name:       "go",
		Extensions: []string{".go"},
		FuncDef:    regexp.MustCompile(`func\s+(?:\([^)]*\)\s+)?(\w+)`),
		StructDef:  regexp.MustCompile(`type\s+(\w+)\s+struct`),
	},
	{
		Name:       "typescript",
		Extensions: []string{".ts", ".tsx", ".js", ".jsx"},
		FuncDef:    regexp.MustCompile(`(?:export\s+)?(?:async\s+)?function\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:export\s+)?class\s+(\w+)`),
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		FuncDef:    regexp.MustCompile(`def\s+(\w+)`),
		StructDef:  regexp.MustCompile(`class\s+(\w+)`),
	},
	{
		Name:       "solidity",
		Extensions: []string{".sol"},
		FuncDef:    regexp.MustCompile(`function\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:contract|interface|library)\s+(\w+)`),
	},
}

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "target": true,
	"build": true, "dist": true, "__pycache__": true, ".venv": true,
}

func langForExt(ext string) *LangRule {
	for i := range defaultLangs {
		for _, e := range defaultLangs[i].Extensions {
			if e == ext {
				return &defaultLangs[i]
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Write adapter.go**

```go
// internal/scanner/regex/adapter.go
package regex

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string      { return "regex" }
func (a *Adapter) Available() bool    { return true }

func (a *Adapter) ExtractGraph(ctx context.Context, req scanner.GraphRequest) (scanner.GraphResult, error) {
	var result scanner.GraphResult
	symbolsByFile := make(map[string][]string) // path -> list of symbol names

	err := filepath.Walk(req.RepoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		lang := langForExt(ext)

		rel, relErr := filepath.Rel(req.RepoRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		fileID := fmt.Sprintf("file-%s", sanitizeID(rel))
		langName := ""
		if lang != nil {
			langName = lang.Name
		}

		result.Nodes = append(result.Nodes, scanner.GraphNode{
			ID:       fileID,
			Kind:     "file",
			Name:     info.Name(),
			Path:     rel,
			Language: langName,
		})

		if lang == nil {
			return nil
		}

		// Extract symbols
		symbols := extractSymbols(path, rel, lang)
		for _, sym := range symbols {
			result.Nodes = append(result.Nodes, sym.node)
			result.Edges = append(result.Edges, scanner.GraphEdge{
				Source: fileID,
				Target: sym.node.ID,
				Kind:   "defines",
			})
			symbolsByFile[rel] = append(symbolsByFile[rel], sym.node.Name)
		}

		return nil
	})
	if err != nil {
		return scanner.GraphResult{}, err
	}

	// Cross-file reference detection
	callEdges := detectCrossFileRefs(req.RepoRoot, result.Nodes, symbolsByFile)
	result.Edges = append(result.Edges, callEdges...)

	return result, nil
}

type symbolInfo struct {
	node scanner.GraphNode
}

func extractSymbols(fullPath, relPath string, lang *LangRule) []symbolInfo {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var symbols []symbolInfo
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()

		if lang.FuncDef != nil {
			if matches := lang.FuncDef.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]
				if !seen[name] && isValidSymbol(name) {
					seen[name] = true
					symbols = append(symbols, symbolInfo{
						node: scanner.GraphNode{
							ID:       fmt.Sprintf("sym-%s-%s", sanitizeID(relPath), name),
							Kind:     "function",
							Name:     name,
							Path:     relPath,
							Language: lang.Name,
						},
					})
				}
			}
		}

		if lang.StructDef != nil {
			if matches := lang.StructDef.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]
				if !seen[name] && isValidSymbol(name) {
					seen[name] = true
					symbols = append(symbols, symbolInfo{
						node: scanner.GraphNode{
							ID:       fmt.Sprintf("sym-%s-%s", sanitizeID(relPath), name),
							Kind:     "struct",
							Name:     name,
							Path:     relPath,
							Language: lang.Name,
						},
					})
				}
			}
		}
	}
	return symbols
}

func detectCrossFileRefs(repoRoot string, nodes []scanner.GraphNode, symbolsByFile map[string][]string) []scanner.GraphEdge {
	// Collect all function symbols
	type symRef struct {
		id   string
		path string
	}
	funcSymbols := make(map[string]symRef) // name -> symRef
	for _, n := range nodes {
		if n.Kind == "function" {
			funcSymbols[n.Name] = symRef{id: n.ID, path: n.Path}
		}
	}

	var edges []scanner.GraphEdge
	seen := make(map[string]bool)

	for filePath, symsInFile := range symbolsByFile {
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(filePath))
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		text := string(content)

		for name, ref := range funcSymbols {
			if ref.path == filePath {
				continue // Skip self-references
			}
			if strings.Contains(text, name) {
				// Find which symbol in this file references it
				for _, localSym := range symsInFile {
					localID := fmt.Sprintf("sym-%s-%s", sanitizeID(filePath), localSym)
					edgeKey := localID + "->" + ref.id
					if !seen[edgeKey] {
						seen[edgeKey] = true
						edges = append(edges, scanner.GraphEdge{
							Source: localID,
							Target: ref.id,
							Kind:   "calls",
						})
						break // One edge per file is enough
					}
				}
			}
		}
	}
	return edges
}

func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "\\", "-", ".", "-", " ", "-")
	return r.Replace(s)
}

func isValidSymbol(name string) bool {
	// Skip common noise: test, main, new, etc. for very short names
	if len(name) < 2 {
		return false
	}
	// Skip Go test functions, init, etc.
	switch name {
	case "init", "main":
		return true // These are valid
	}
	return true
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/regex/ -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/regex/
git commit -m "feat(scanner): add regex graph adapter with multi-language support"
```

---

## Task 5: Semgrep/CodeQL/Joern Graph Adapter Stubs

**Files:**
- Create: `internal/scanner/semgrep/adapter.go`
- Create: `internal/scanner/codeql/adapter.go`
- Create: `internal/scanner/joern/adapter.go`

- [ ] **Step 1: Create all three stubs**

```go
// internal/scanner/semgrep/adapter.go
package semgrep

import (
	"context"
	"os/exec"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (a *Adapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	// Semgrep graph extraction: future implementation
	// Will use semgrep --json with custom rules to extract function defs and calls
	return scanner.GraphResult{}, nil
}
```

```go
// internal/scanner/codeql/adapter.go
package codeql

import (
	"context"
	"errors"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "codeql" }
func (a *Adapter) Available() bool { return false }

func (a *Adapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return scanner.GraphResult{}, errors.New("codeql graph adapter not implemented")
}
```

```go
// internal/scanner/joern/adapter.go
package joern

import (
	"context"
	"errors"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "joern" }
func (a *Adapter) Available() bool { return false }

func (a *Adapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return scanner.GraphResult{}, errors.New("joern graph adapter not implemented")
}
```

- [ ] **Step 2: Verify build**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/scanner/...`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/semgrep/ internal/scanner/codeql/ internal/scanner/joern/
git commit -m "feat(scanner): add semgrep/codeql/joern graph adapter stubs"
```

---

## Task 6: Scan Orchestrator (Heuristic + LLM)

**Files:**
- Create: `internal/scanner/scan.go`
- Create: `internal/scanner/scan_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/scan_test.go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

func TestScanHeuristic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "verify.rs"), []byte(`
pub fn verify_quote() {}
fn check_policy() {}
pub struct Report {}
`), 0o644)
	os.WriteFile(filepath.Join(src, "state.rs"), []byte(`
pub fn apply_transition() {}
`), 0o644)

	result, err := scanner.Scan(context.Background(), scanner.ScanRequest{
		RepoRoot: dir,
		Mode:     "heuristic",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Nodes) == 0 {
		t.Fatal("expected nodes")
	}
	if len(result.Edges) == 0 {
		t.Fatal("expected edges")
	}

	// Check we got file and function nodes
	hasFile := false
	hasFunc := false
	for _, n := range result.Nodes {
		if n.Kind == "file" {
			hasFile = true
		}
		if n.Kind == "function" {
			hasFunc = true
		}
	}
	if !hasFile || !hasFunc {
		t.Fatalf("expected file and function nodes, got: %+v", result.Nodes)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/ -v -run TestScan`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```go
// internal/scanner/scan.go
package scanner

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/regex"
	scanSemgrep "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/semgrep"
)

type ScanRequest struct {
	RepoRoot  string
	Languages []string
	Focus     string
	Mode      string // "heuristic" or "llm"
}

func NewDefaultGraphRegistry() *GraphRegistry {
	r := NewGraphRegistry()
	r.Register(regex.New())
	r.Register(scanSemgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}

func Scan(ctx context.Context, req ScanRequest) (GraphResult, error) {
	reg := NewDefaultGraphRegistry()

	if req.Mode == "llm" {
		return scanLLM(ctx, reg, req)
	}
	return scanHeuristic(ctx, reg, req)
}

func scanHeuristic(ctx context.Context, reg *GraphRegistry, req ScanRequest) (GraphResult, error) {
	graphReq := GraphRequest{
		RepoRoot:  req.RepoRoot,
		Languages: req.Languages,
		Focus:     req.Focus,
	}
	result, err := reg.RunAll(ctx, graphReq)
	if err != nil {
		return GraphResult{}, fmt.Errorf("scan heuristic: %w", err)
	}
	fmt.Printf("Graph scan complete: %d nodes, %d edges (tools: %v)\n",
		len(result.Nodes), len(result.Edges), reg.Available())
	return result, nil
}

func scanLLM(ctx context.Context, reg *GraphRegistry, req ScanRequest) (GraphResult, error) {
	// In LLM mode, for now we still run all available tools.
	// The LLM tool-selection loop will be wired in when the pipeline
	// agent calls this with a bus + LLM client.
	// This is the entry point where the Scanner agent's LLM will
	// decide which tools to run and review intermediate results.
	return scanHeuristic(ctx, reg, req)
}
```

Note: The full LLM tool-selection loop (where the Scanner agent LLM decides which tools to use) will be wired through the pipeline's Scanner agent, which has access to the bus and LLM client. The `scanLLM` function here is the hook point — for now it falls back to heuristic. The pipeline agent will call the registry directly with LLM-guided tool selection.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scan.go internal/scanner/scan_test.go
git commit -m "feat(scanner): add scan orchestrator with heuristic and LLM modes"
```

---

## Task 7: Config + runfs Changes

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/runfs/paths.go`

- [ ] **Step 1: Add Target and Mode fields to Config**

In `internal/config/config.go`, add to Config struct after `MaxDialogRounds int`:

```go
Target string
Mode   string
```

- [ ] **Step 2: Add parseRun function**

```go
func parseRun(args []string) (Config, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg := Config{
		Command:         "run",
		Focus:           "tee",
		OutputDir:       filepath.Clean("runs"),
		KnowledgeRoot:   filepath.Clean("knowledge"),
		MaxHotspots:     12,
		MaxCases:        12,
		MaxDialogRounds: 3,
		Mode:            "heuristic",
		StaticTools:     "auto",
		LLMProvider:     firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:      firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:       firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:        firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec:   envInt(60, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMTemp:         envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "Agent mode: heuristic or llm")
	fs.StringVar(&cfg.Focus, "focus", cfg.Focus, "Audit focus area")
	fs.StringVar(&cfg.RunID, "run-id", "", "Stable run identifier")
	fs.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Output directory")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root")
	fs.IntVar(&cfg.MaxCases, "max-cases", cfg.MaxCases, "Maximum case packs")
	fs.IntVar(&cfg.MaxHotspots, "max-hotspots", cfg.MaxHotspots, "Maximum hotspots")
	fs.IntVar(&cfg.MaxDialogRounds, "max-dialog-rounds", cfg.MaxDialogRounds, "Maximum dialog rounds")
	fs.StringVar(&cfg.StaticTools, "static-tools", cfg.StaticTools, "Static tools")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "LLM base URL")
	fs.StringVar(&cfg.LLMAPIKey, "llm-api-key", cfg.LLMAPIKey, "LLM API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "LLM model name")
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "LLM timeout")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "LLM temperature")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// First non-flag arg is the target (URL or path)
	remaining := fs.Args()
	if len(remaining) == 0 {
		return Config{}, fmt.Errorf("run requires a target (URL or local path)")
	}
	cfg.Target = remaining[0]

	// Map --mode to all agent modes
	if cfg.Mode == "llm" {
		cfg.ExpertMode = "llm"
		cfg.ChallengeMode = "llm"
		cfg.VerifierMode = "llm"
		cfg.ArbiterMode = "llm"
		cfg.CuratorMode = "llm"
		if err := validateProviderConfig(cfg, "run"); err != nil {
			return Config{}, err
		}
	}

	return cfg, nil
}
```

- [ ] **Step 3: Add routing in Parse switch**

Add before `default:`:

```go
case "run":
	return parseRun(args[1:])
```

- [ ] **Step 4: Add new runfs paths**

Append to `internal/runfs/paths.go`:

```go
func GraphDir(runDir string) string {
	return filepath.Join(runDir, "02_graph")
}

func GraphPath(runDir string) string {
	return filepath.Join(runDir, "02_graph", "graph.json")
}

func ScannerDir(runDir string) string {
	return filepath.Join(runDir, "06_scanner")
}

func ReviewerDir(runDir string) string {
	return filepath.Join(runDir, "07_reviewer")
}

func AuditorDir(runDir string) string {
	return filepath.Join(runDir, "08_auditor")
}

func AuditorPacketsDir(runDir string) string {
	return filepath.Join(runDir, "08_auditor", "packets")
}

func AuditorFindingsPath(runDir string) string {
	return filepath.Join(runDir, "08_auditor", "findings.json")
}
```

- [ ] **Step 5: Update usageError**

Add to usage string:

```
  teecheck run <url-or-path> [--mode heuristic|llm] [--focus NAME] [--max-cases N] [--llm-base-url URL] [--llm-model NAME]
```

- [ ] **Step 6: Verify build**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/config/ ./internal/runfs/`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/runfs/paths.go
git commit -m "feat(config): add teecheck run command with Target and Mode fields"
```

---

## Task 8: Pipeline — 3-Agent Orchestrator

**Files:**
- Create: `internal/pipeline/run.go`
- Create: `internal/pipeline/run_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/pipeline/run_test.go
package pipeline_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPipelineHeuristic(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "run",
		Target:        filepath.Join(root, "testdata", "sample_repo"),
		Mode:          "heuristic",
		Focus:         "runtime",
		RunID:         "pipeline-test-001",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		MaxHotspots:   4,
		MaxCases:      4,
		StaticTools:   "auto",
	}

	runDir, err := pipeline.Run(cfg)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	// Check key artifacts exist
	for _, path := range []string{
		runfs.ProjectProfilePath(runDir),
		runfs.GraphPath(runDir),
		filepath.Join(runfs.AuditorDir(runDir), "findings.json"),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact %s: %v", path, statErr)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/pipeline/ -v`
Expected: FAIL

- [ ] **Step 3: Write the implementation**

```go
// internal/pipeline/run.go
package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func Run(cfg config.Config) (string, error) {
	// === Repo Acquisition ===
	fetch, err := repofetch.Fetch(cfg.Target)
	if err != nil {
		return "", fmt.Errorf("fetch repo: %w", err)
	}
	if fetch.Cloned {
		fmt.Printf("Cloned %s to %s (commit: %s)\n", fetch.RepoURL, fetch.LocalPath, fetch.Commit[:12])
	} else {
		fmt.Printf("Using local repo at %s (commit: %s)\n", fetch.LocalPath, fetch.Commit[:min(12, len(fetch.Commit))])
	}

	// Populate config fields from fetch result
	cfg.LocalPath = fetch.LocalPath
	cfg.Commit = fetch.Commit
	if fetch.RepoURL != "" {
		cfg.RepoURL = fetch.RepoURL
	} else {
		cfg.RepoURL = fetch.LocalPath
	}

	// === Init Run ===
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return "", fmt.Errorf("ensure knowledge layout: %w", err)
	}
	initCfg := cfg
	initCfg.Command = "init-run"
	runDir, err := runinit.Run(initCfg, time.Now())
	if err != nil {
		return "", fmt.Errorf("init run: %w", err)
	}

	stageCfg := cfg
	stageCfg.RunDir = runDir

	// === Agent 1: Scanner ===
	fmt.Println("\n=== Scanner Agent ===")

	// Step 1: Project profile
	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}

	// Step 2: Generate code graph
	scanMode := "heuristic"
	if strings.EqualFold(cfg.Mode, "llm") {
		scanMode = "llm"
	}
	graphResult, err := scanner.Scan(context.Background(), scanner.ScanRequest{
		RepoRoot: fetch.LocalPath,
		Focus:    cfg.Focus,
		Mode:     scanMode,
	})
	if err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}
	graphPath := runfs.GraphPath(runDir)
	if err := runfs.WriteJSON(graphPath, graphResult); err != nil {
		return "", fmt.Errorf("write graph: %w", err)
	}
	fmt.Printf("Graph generated: %d nodes, %d edges → %s\n", len(graphResult.Nodes), len(graphResult.Edges), graphPath)

	// Step 3: Mapper (use generated graph)
	stageCfg.GraphJSONPath = graphPath
	if err := mapper.Run(stageCfg); err != nil {
		return "", fmt.Errorf("mapper: %w", err)
	}

	// Step 4: Cases
	if err := cases.Run(stageCfg); err != nil {
		return "", fmt.Errorf("cases: %w", err)
	}

	// Step 5: Expert hypotheses
	stageCfg.AgentID = "scanner-001"
	if err := expert.Run(stageCfg); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	// === Agent 2: Reviewer ===
	fmt.Println("\n=== Reviewer Agent ===")

	needsBus := strings.EqualFold(cfg.Mode, "llm")

	if needsBus {
		bus := buildPipelineBus(cfg)

		// Register Scanner as tool handler on bus
		scReg := scall.NewDefaultRegistry()
		bus.Register("scanner-001", agentbus.NewToolHandler("scanner", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
			req := staticcheck.CheckRequest{
				RepoRoot: fetch.LocalPath,
				Keywords: strings.Fields(q.Question),
			}
			findings, runErr := scReg.RunAll(ctx, req)
			if runErr != nil {
				return agentbus.Response{}, runErr
			}
			var facts []string
			for _, f := range findings {
				facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
			}
			return agentbus.Response{
				QueryID:   q.QueryID,
				FromAgent: "scanner-001",
				Answer:    fmt.Sprintf("Found %d results", len(findings)),
				Facts:     facts,
			}, nil
		}))

		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.RunWithBus(stageCfg, bus); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	} else {
		stageCfg.AgentID = "reviewer-001"
		if err := challenger.Run(stageCfg); err != nil {
			return "", fmt.Errorf("challenger: %w", err)
		}
		if err := verifier.Run(stageCfg); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		// === Agent 3: Auditor ===
		fmt.Println("\n=== Auditor Agent ===")
		stageCfg.AgentID = "auditor-001"
		if err := arbiter.Run(stageCfg); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	}

	// Print summary
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err == nil {
		fmt.Printf("\n=== Complete ===\nRun: %s\nFindings: %d\n", runDir, len(findings.Findings))
		for _, f := range findings.Findings {
			fmt.Printf("  [%s] %s — %s (confidence: %s)\n", f.Severity, f.FindingID, f.Status, f.Confidence)
		}
	}

	return runDir, nil
}

func buildPipelineBus(cfg config.Config) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)

	client := llm.NewClient(cfg)
	bus.Register("expert-001", agentbus.NewLLMHandler(client,
		"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("challenger-001", agentbus.NewLLMHandler(client,
		"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("reviewer-001", agentbus.NewLLMHandler(client,
		"You are the Reviewer Agent in TEECheck. Another agent asks you about your verification. Return a JSON object with fields: answer (string), facts (array of strings).",
		cfg.LLMTemp))

	return bus
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
```

Note: This imports `artifacts` — add `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/pipeline/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/pipeline/
git commit -m "feat(pipeline): add 3-agent pipeline orchestrator"
```

---

## Task 9: Wire Into main.go

**Files:**
- Modify: `cmd/teecheck/main.go`

- [ ] **Step 1: Add import and routing**

Add import: `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"`

Add case in switch:

```go
case "run":
	var runPath string
	runPath, err = pipeline.Run(cfg)
	if err == nil {
		fmt.Printf("\nPipeline completed. Results at %s\n", runPath)
	}
```

- [ ] **Step 2: Verify build**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./cmd/teecheck/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add cmd/teecheck/main.go
git commit -m "feat: wire teecheck run command into CLI"
```

---

## Task 10: End-to-End Smoke Test

**Files:** (no new files)

- [ ] **Step 1: Run heuristic mode on sample_repo**

Run:
```bash
cd /root/pp_home/idea/TEECheck/tee-usage-scanner && \
go run ./cmd/teecheck/ run testdata/sample_repo --focus runtime --max-cases 2 --run-id smoke-test-001
```
Expected: Completes without error, prints findings summary

- [ ] **Step 2: Run full test suite**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./... -v 2>&1 | tail -30`
Expected: All tests PASS

- [ ] **Step 3: Verify graph was auto-generated**

Run: `cat runs/smoke-test-001/02_graph/graph.json | python3 -m json.tool | head -20`
Expected: Valid JSON with nodes and edges

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Repo fetch | `repofetch/fetch.go` |
| 2 | Graph adapter types | `scanner/graph_adapter.go` |
| 3 | Graph registry + merge | `scanner/registry.go`, `scanner/merge.go` |
| 4 | Regex graph adapter + langs | `scanner/regex/adapter.go`, `scanner/regex/langs.go` |
| 5 | Semgrep/CodeQL/Joern stubs | `scanner/{semgrep,codeql,joern}/adapter.go` |
| 6 | Scan orchestrator | `scanner/scan.go` |
| 7 | Config + runfs changes | `config/config.go`, `runfs/paths.go` |
| 8 | 3-agent pipeline | `pipeline/run.go` |
| 9 | Wire into main.go | `cmd/teecheck/main.go` |
| 10 | Smoke test | (verification only) |
