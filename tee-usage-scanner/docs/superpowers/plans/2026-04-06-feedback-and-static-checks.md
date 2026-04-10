# Human Feedback And Static Check Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pluggable static analysis adapter framework and interactive CLI human review with feedback writeback to the knowledge layer.

**Architecture:** Three new packages (`staticcheck`, `review`, `feedback`) plus changes to `artifacts`, `config`, `runfs`, and `cmd/teecheck/main.go`. Static check adapters implement a common interface registered in a central registry. The review package drives interactive terminal sessions over arbiter packets. The feedback package archives review records to `knowledge/learned/` and appends learned entries to wiki pages.

**Tech Stack:** Go 1.25, stdlib only (bufio for terminal I/O, os/exec for Semgrep), no external dependencies.

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `internal/staticcheck/adapter.go` | `Adapter` interface, `CheckRequest`, `CheckFinding`, `ErrNotImplemented` |
| `internal/staticcheck/registry.go` | `Registry` struct with register/get/run methods, `NewDefaultRegistry()` |
| `internal/staticcheck/registry_test.go` | Tests for registry dispatch logic |
| `internal/staticcheck/grep/adapter.go` | Grep adapter using keyword search over files |
| `internal/staticcheck/grep/adapter_test.go` | Tests for grep adapter |
| `internal/staticcheck/semgrep/adapter.go` | Semgrep adapter shelling out to `semgrep --json` |
| `internal/staticcheck/semgrep/adapter_test.go` | Tests for semgrep adapter (mocked) |
| `internal/staticcheck/codeql/adapter.go` | Stub returning `ErrNotImplemented` |
| `internal/staticcheck/joern/adapter.go` | Stub returning `ErrNotImplemented` |
| `internal/review/run.go` | `Run(cfg)` main loop: load packets, iterate, write results |
| `internal/review/prompt.go` | Terminal I/O: read verdict, tags, notes from stdin |
| `internal/review/display.go` | Format and render review packet summary to terminal |
| `internal/review/run_test.go` | Test review flow with simulated stdin |
| `internal/feedback/run.go` | Read review records, archive to learned, append to wiki |
| `internal/feedback/run_test.go` | Test feedback archival and wiki append logic |

### Modified Files

| File | Changes |
|------|---------|
| `internal/artifacts/types.go` | Add `ReviewRecord` and `CheckFinding` types |
| `internal/runfs/paths.go` | Add `ReviewDir()`, `ReviewRecordsPath()` |
| `internal/config/config.go` | Add `StaticTools` field, `review` and `feedback` subcommand parsers |
| `cmd/teecheck/main.go` | Add `review` and `feedback` command routing |
| `internal/verifier/run.go` | Integrate static check registry into `buildMemo()` |

---

## Task 1: Core Static Check Types

**Files:**
- Create: `internal/staticcheck/adapter.go`

- [ ] **Step 1: Create the staticcheck package with core types**

```go
// internal/staticcheck/adapter.go
package staticcheck

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("adapter not implemented")

type CheckRequest struct {
	RepoRoot    string
	TargetFiles []string
	Keywords    []string
	RuleIDs     []string
	Category    string
	ExtraArgs   map[string]string
}

type CheckFinding struct {
	ToolName  string `json:"tool_name"`
	RuleID    string `json:"rule_id,omitempty"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line,omitempty"`
	Message   string `json:"message"`
	Severity  string `json:"severity,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

type Adapter interface {
	Name() string
	Available() bool
	Run(ctx context.Context, req CheckRequest) ([]CheckFinding, error)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/staticcheck/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/staticcheck/adapter.go
git commit -m "feat(staticcheck): add core Adapter interface and types"
```

---

## Task 2: Registry

**Files:**
- Create: `internal/staticcheck/registry.go`
- Create: `internal/staticcheck/registry_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/staticcheck/registry_test.go
package staticcheck_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type fakeAdapter struct {
	name      string
	available bool
	findings  []staticcheck.CheckFinding
}

func (f *fakeAdapter) Name() string      { return f.name }
func (f *fakeAdapter) Available() bool    { return f.available }
func (f *fakeAdapter) Run(_ context.Context, _ staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	return f.findings, nil
}

func TestRegistryRunAll(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{
		name: "tool-a", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-a", Path: "a.rs", Message: "hit-a"}},
	})
	reg.Register(&fakeAdapter{name: "tool-b", available: false})
	reg.Register(&fakeAdapter{
		name: "tool-c", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-c", Path: "c.rs", Message: "hit-c"}},
	})

	results, err := reg.RunAll(context.Background(), staticcheck.CheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(results))
	}
	if results[0].ToolName != "tool-a" || results[1].ToolName != "tool-c" {
		t.Fatalf("unexpected findings: %+v", results)
	}
}

func TestRegistryRunByName(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{
		name: "tool-a", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-a", Path: "a.rs", Message: "hit"}},
	})

	results, err := reg.RunByName(context.Background(), "tool-a", staticcheck.CheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	_, err = reg.RunByName(context.Background(), "missing", staticcheck.CheckRequest{})
	if err == nil {
		t.Fatal("expected error for missing adapter")
	}
}

func TestRegistryAvailable(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{name: "yes", available: true})
	reg.Register(&fakeAdapter{name: "no", available: false})

	avail := reg.Available()
	if len(avail) != 1 || avail[0] != "yes" {
		t.Fatalf("expected [yes], got %v", avail)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/ -v`
Expected: FAIL — `NewRegistry`, `RunAll`, `RunByName`, `Available` not defined

- [ ] **Step 3: Write the implementation**

```go
// internal/staticcheck/registry.go
package staticcheck

import (
	"context"
	"fmt"
	"sort"
)

type Registry struct {
	adapters map[string]Adapter
	order    []string
}

func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

func (r *Registry) Register(a Adapter) {
	name := a.Name()
	if _, exists := r.adapters[name]; !exists {
		r.order = append(r.order, name)
	}
	r.adapters[name] = a
}

func (r *Registry) Get(name string) (Adapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

func (r *Registry) Available() []string {
	var names []string
	for _, name := range r.order {
		if r.adapters[name].Available() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *Registry) RunAll(ctx context.Context, req CheckRequest) ([]CheckFinding, error) {
	var all []CheckFinding
	for _, name := range r.order {
		a := r.adapters[name]
		if !a.Available() {
			continue
		}
		findings, err := a.Run(ctx, req)
		if err != nil {
			return all, fmt.Errorf("adapter %s: %w", name, err)
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (r *Registry) RunByName(ctx context.Context, name string, req CheckRequest) ([]CheckFinding, error) {
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("unknown adapter: %s", name)
	}
	if !a.Available() {
		return nil, fmt.Errorf("adapter %s is not available", name)
	}
	return a.Run(ctx, req)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/staticcheck/registry.go internal/staticcheck/registry_test.go
git commit -m "feat(staticcheck): add Registry with RunAll and RunByName"
```

---

## Task 3: Grep Adapter

**Files:**
- Create: `internal/staticcheck/grep/adapter.go`
- Create: `internal/staticcheck/grep/adapter_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/staticcheck/grep/adapter_test.go
package grep_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
)

func TestGrepAdapterFindsKeywords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.rs"), []byte("fn verify_quote() {\n    // TODO check freshness\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := grep.New()
	if a.Name() != "grep" {
		t.Fatalf("expected name grep, got %s", a.Name())
	}
	if !a.Available() {
		t.Fatal("expected grep to be available")
	}

	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    dir,
		TargetFiles: []string{"sample.rs"},
		Keywords:    []string{"todo", "verify"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.ToolName != "grep" {
			t.Fatalf("expected tool_name grep, got %s", f.ToolName)
		}
	}
}

func TestGrepAdapterNoResults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.rs"), []byte("fn safe() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := grep.New()
	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    dir,
		TargetFiles: []string{"clean.rs"},
		Keywords:    []string{"vulnerability"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/grep/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Write the implementation**

```go
// internal/staticcheck/grep/adapter.go
package grep

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string      { return "grep" }
func (a *Adapter) Available() bool    { return true }

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	keywords := lowerAll(req.Keywords)
	if len(keywords) == 0 {
		return nil, nil
	}
	targets := req.TargetFiles
	if len(targets) == 0 {
		targets = []string{"."}
	}

	var findings []staticcheck.CheckFinding
	for _, rel := range targets {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		full := filepath.Join(req.RepoRoot, rel)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.IsDir() {
			dirFindings, err := a.walkDir(ctx, full, req.RepoRoot, keywords)
			if err != nil {
				return findings, err
			}
			findings = append(findings, dirFindings...)
		} else {
			fileFindings := searchFile(full, req.RepoRoot, keywords)
			findings = append(findings, fileFindings...)
		}
	}
	return findings, nil
}

func (a *Adapter) walkDir(ctx context.Context, dir, repoRoot string, keywords []string) ([]staticcheck.CheckFinding, error) {
	var findings []staticcheck.CheckFinding
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		findings = append(findings, searchFile(path, repoRoot, keywords)...)
		return nil
	})
	return findings, err
}

func searchFile(fullPath, repoRoot string, keywords []string) []staticcheck.CheckFinding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	rel, err := filepath.Rel(repoRoot, fullPath)
	if err != nil {
		rel = fullPath
	}

	var findings []staticcheck.CheckFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, staticcheck.CheckFinding{
					ToolName:  "grep",
					Path:      filepath.ToSlash(rel),
					StartLine: lineNum,
					Message:   strings.TrimSpace(line),
					Severity:  "info",
					Snippet:   strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return findings
}

func lowerAll(values []string) []string {
	var out []string
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/grep/ -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/staticcheck/grep/
git commit -m "feat(staticcheck): add grep adapter"
```

---

## Task 4: Semgrep Adapter

**Files:**
- Create: `internal/staticcheck/semgrep/adapter.go`
- Create: `internal/staticcheck/semgrep/adapter_test.go`

- [ ] **Step 1: Write the failing test**

The test mocks the exec call by testing the JSON parsing logic separately, so it works without semgrep installed.

```go
// internal/staticcheck/semgrep/adapter_test.go
package semgrep

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

func TestParseSemgrepOutput(t *testing.T) {
	raw := []byte(`{
		"results": [
			{
				"check_id": "rules.tee.missing-attestation",
				"path": "src/verify.rs",
				"start": {"line": 42, "col": 1},
				"end": {"line": 42, "col": 30},
				"extra": {
					"message": "Missing attestation check",
					"severity": "WARNING",
					"lines": "    let quote = get_quote();"
				}
			}
		]
	}`)

	findings, err := parseSemgrepJSON(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ToolName != "semgrep" {
		t.Fatalf("expected tool_name semgrep, got %s", f.ToolName)
	}
	if f.RuleID != "rules.tee.missing-attestation" {
		t.Fatalf("unexpected rule_id: %s", f.RuleID)
	}
	if f.Path != "src/verify.rs" {
		t.Fatalf("unexpected path: %s", f.Path)
	}
	if f.StartLine != 42 {
		t.Fatalf("expected start_line 42, got %d", f.StartLine)
	}
	if f.Message != "Missing attestation check" {
		t.Fatalf("unexpected message: %s", f.Message)
	}
}

func TestParseSemgrepEmptyResults(t *testing.T) {
	raw := []byte(`{"results": []}`)
	findings, err := parseSemgrepJSON(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestAdapterName(t *testing.T) {
	a := New()
	if a.Name() != "semgrep" {
		t.Fatalf("expected name semgrep, got %s", a.Name())
	}
}

// Available() depends on host, so we just verify it returns without panic.
func TestAdapterAvailable(t *testing.T) {
	a := New()
	_ = a.Available()
}

// Verify the adapter satisfies the interface at compile time.
var _ staticcheck.Adapter = (*Adapter)(nil)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/semgrep/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Write the implementation**

```go
// internal/staticcheck/semgrep/adapter.go
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	args := []string{"--json", "--no-git-ignore"}

	configPath := "auto"
	if v, ok := req.ExtraArgs["config"]; ok && v != "" {
		configPath = v
	}
	args = append(args, "--config="+configPath)

	for _, f := range req.TargetFiles {
		args = append(args, "--include="+f)
	}

	args = append(args, req.RepoRoot)

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// semgrep exits 1 when it finds results; use combined output
			if len(out) == 0 {
				out = exitErr.Stderr
			}
		} else {
			return nil, fmt.Errorf("semgrep exec: %w", err)
		}
	}

	return parseSemgrepJSON(out)
}

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
}

func parseSemgrepJSON(data []byte) ([]staticcheck.CheckFinding, error) {
	var output semgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}

	findings := make([]staticcheck.CheckFinding, 0, len(output.Results))
	for _, r := range output.Results {
		findings = append(findings, staticcheck.CheckFinding{
			ToolName:  "semgrep",
			RuleID:    r.CheckID,
			Path:      r.Path,
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
			Message:   r.Extra.Message,
			Severity:  normalizeSeverity(r.Extra.Severity),
			Snippet:   r.Extra.Lines,
		})
	}
	return findings, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	default:
		return "info"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/staticcheck/semgrep/ -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/staticcheck/semgrep/
git commit -m "feat(staticcheck): add semgrep adapter"
```

---

## Task 5: CodeQL And Joern Stubs

**Files:**
- Create: `internal/staticcheck/codeql/adapter.go`
- Create: `internal/staticcheck/joern/adapter.go`

- [ ] **Step 1: Create CodeQL stub**

```go
// internal/staticcheck/codeql/adapter.go
package codeql

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "codeql" }
func (a *Adapter) Available() bool { return false }

func (a *Adapter) Run(_ context.Context, _ staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	return nil, staticcheck.ErrNotImplemented
}
```

- [ ] **Step 2: Create Joern stub**

```go
// internal/staticcheck/joern/adapter.go
package joern

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "joern" }
func (a *Adapter) Available() bool { return false }

func (a *Adapter) Run(_ context.Context, _ staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	return nil, staticcheck.ErrNotImplemented
}
```

- [ ] **Step 3: Add NewDefaultRegistry to registry.go**

Append to `internal/staticcheck/registry.go`:

```go
import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(grep.New())
	r.Register(semgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
```

Note: this requires moving `NewDefaultRegistry` to a separate file (`internal/staticcheck/defaults.go`) to avoid an import cycle, since `registry.go` is in the `staticcheck` package and the adapters import `staticcheck`. The solution:

```go
// internal/staticcheck/defaults.go
package staticcheck

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(grep.New())
	r.Register(semgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
```

**Wait — this IS a circular import.** The adapters import `staticcheck` for the interface, and `staticcheck` would import the adapters. The fix: `NewDefaultRegistry` lives in a separate bootstrap package or at the call site. Better approach: callers build the registry themselves, or we put `NewDefaultRegistry` at the `cmd` level.

Revised approach — add a helper in a new file `internal/staticcheck/build.go` that does NOT import adapter packages. Instead, `NewDefaultRegistry` is a function in `cmd/teecheck/main.go` or a thin `internal/staticcheck/all/all.go` package:

```go
// internal/staticcheck/all/all.go
package all

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

func NewDefaultRegistry() *staticcheck.Registry {
	r := staticcheck.NewRegistry()
	r.Register(grep.New())
	r.Register(semgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/staticcheck/... && go test ./internal/staticcheck/ -v`
Expected: builds clean, existing registry tests still pass

- [ ] **Step 5: Commit**

```bash
git add internal/staticcheck/codeql/ internal/staticcheck/joern/ internal/staticcheck/all/
git commit -m "feat(staticcheck): add codeql/joern stubs and default registry builder"
```

---

## Task 6: ReviewRecord Type And runfs Paths

**Files:**
- Modify: `internal/artifacts/types.go`
- Modify: `internal/runfs/paths.go`

- [ ] **Step 1: Add ReviewRecord to artifacts/types.go**

Append after the `VerificationMemo` struct (after line 185):

```go
type ReviewRecord struct {
	SchemaVersion string   `json:"schema_version"`
	CaseID        string   `json:"case_id"`
	FindingID     string   `json:"finding_id"`
	Verdict       string   `json:"verdict"`
	Severity      string   `json:"severity"`
	Tags          []string `json:"tags,omitempty"`
	Notes         string   `json:"notes,omitempty"`
	ReviewerID    string   `json:"reviewer_id,omitempty"`
	ReviewedAt    string   `json:"reviewed_at"`
}
```

- [ ] **Step 2: Add review paths to runfs/paths.go**

Append after `ArbiterFindingsPath` (after line 54):

```go
func ReviewDir(runDir string) string {
	return filepath.Join(runDir, "08_review")
}

func ReviewRecordsPath(runDir string) string {
	return filepath.Join(runDir, "08_review", "review_records.jsonl")
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/artifacts/ ./internal/runfs/`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add internal/artifacts/types.go internal/runfs/paths.go
git commit -m "feat: add ReviewRecord type and review runfs paths"
```

---

## Task 7: Config Changes — StaticTools, Review, Feedback Subcommands

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add StaticTools field to Config struct**

In `internal/config/config.go`, add after line 34 (`LLMTemp float64`):

```go
StaticTools string
```

- [ ] **Step 2: Add StaticTools flag to parseCollabRun**

In `parseCollabRun`, add after the `LLMTemp` flag (after line 109):

```go
fs.StringVar(&cfg.StaticTools, "static-tools", "auto", "Static tools to enable: auto, none, or comma-separated names (grep,semgrep)")
```

And set the default in the cfg literal: `StaticTools: "auto"`.

- [ ] **Step 3: Add parseReview function**

```go
func parseReview(args []string) (Config, error) {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	cfg := Config{
		Command:       "review",
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing arbiter outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("review requires --run-dir")
	}
	return cfg, nil
}
```

- [ ] **Step 4: Add parseFeedback function**

```go
func parseFeedback(args []string) (Config, error) {
	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	cfg := Config{
		Command:       "feedback",
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing review outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("feedback requires --run-dir")
	}
	return cfg, nil
}
```

- [ ] **Step 5: Add routing in Parse switch**

Add two new cases in the `switch args[0]` block (after the `"arbiter"` case):

```go
case "review":
	return parseReview(args[1:])
case "feedback":
	return parseFeedback(args[1:])
```

- [ ] **Step 6: Update usageError string**

Add to the usage text:

```
  teecheck review --run-dir DIR [--knowledge-root DIR]
  teecheck feedback --run-dir DIR [--knowledge-root DIR]
```

- [ ] **Step 7: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/config/`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add review, feedback subcommands and StaticTools field"
```

---

## Task 8: Interactive Review — Display And Prompt

**Files:**
- Create: `internal/review/display.go`
- Create: `internal/review/prompt.go`

- [ ] **Step 1: Create display.go**

```go
// internal/review/display.go
package review

import (
	"fmt"
	"io"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func DisplayPacketSummary(w io.Writer, idx, total int, finding artifacts.FindingItem, packetText string) {
	bar := strings.Repeat("━", 50)
	fmt.Fprintf(w, "\n%s\n", bar)
	fmt.Fprintf(w, "Case %d/%d: %s\n", idx+1, total, finding.FindingID)
	fmt.Fprintf(w, "Status: %s | Confidence: %s | Severity: %s\n", finding.Status, finding.Confidence, finding.Severity)
	fmt.Fprintf(w, "%s\n\n", bar)
	fmt.Fprintln(w, packetText)
	fmt.Fprintf(w, "%s\n", bar)
}
```

- [ ] **Step 2: Create prompt.go**

```go
// internal/review/prompt.go
package review

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func PromptVerdict(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Verdict? [c]onfirm / [d]ismiss / [i]nconclusive / [s]kip / [q]uit: ")
	if !r.Scan() {
		return "quit"
	}
	switch strings.ToLower(strings.TrimSpace(r.Text())) {
	case "c", "confirm":
		return "confirmed"
	case "d", "dismiss":
		return "dismissed"
	case "i", "inconclusive":
		return "inconclusive"
	case "s", "skip":
		return "skip"
	default:
		return "quit"
	}
}

func PromptSeverityOverride(r *bufio.Scanner, w io.Writer, current string) string {
	fmt.Fprintf(w, "Severity override (high/medium/low) [enter=keep %s]: ", current)
	if !r.Scan() {
		return current
	}
	text := strings.ToLower(strings.TrimSpace(r.Text()))
	switch text {
	case "high", "medium", "low":
		return text
	default:
		return current
	}
}

func PromptTags(r *bufio.Scanner, w io.Writer) []string {
	fmt.Fprint(w, "Tags (comma-separated): ")
	if !r.Scan() {
		return nil
	}
	raw := strings.TrimSpace(r.Text())
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var tags []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}

func PromptNotes(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Notes: ")
	if !r.Scan() {
		return ""
	}
	return strings.TrimSpace(r.Text())
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/review/`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add internal/review/display.go internal/review/prompt.go
git commit -m "feat(review): add display and prompt helpers"
```

---

## Task 9: Interactive Review — Run Loop

**Files:**
- Create: `internal/review/run.go`
- Create: `internal/review/run_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/review/run_test.go
package review_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestReviewFlow(t *testing.T) {
	runDir := t.TempDir()

	// Write a minimal findings.json
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-001",
		Findings: []artifacts.FindingItem{
			{
				FindingID:  "case-001",
				SliceID:    "case-001",
				Status:     "likely_issue",
				Severity:   "high",
				Confidence: "high",
				Files:      []string{"verify.rs"},
				Summary:    "Missing attestation",
			},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findings); err != nil {
		t.Fatal(err)
	}

	// Write a minimal review packet
	packetsDir := runfs.ArbiterPacketsDir(runDir)
	if err := os.MkdirAll(packetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packetsDir, "review-001.md"), []byte("# Review Packet: case-001\n\nSome content here.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Simulate user input: confirm, keep severity, add tag, add note
	input := "c\n\nattestation\nLooks real\n"
	var output bytes.Buffer

	cfg := config.Config{
		Command: "review",
		RunDir:  runDir,
	}
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	err := review.RunWithIO(cfg, strings.NewReader(input), &output, now)
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}

	// Check review-001.json was written
	reviewPath := filepath.Join(runfs.ReviewDir(runDir), "review-001.json")
	data, err := os.ReadFile(reviewPath)
	if err != nil {
		t.Fatalf("review file not found: %v", err)
	}
	var rec artifacts.ReviewRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse review record: %v", err)
	}
	if rec.Verdict != "confirmed" {
		t.Fatalf("expected verdict confirmed, got %s", rec.Verdict)
	}
	if rec.Severity != "high" {
		t.Fatalf("expected severity high, got %s", rec.Severity)
	}
	if len(rec.Tags) != 1 || rec.Tags[0] != "attestation" {
		t.Fatalf("unexpected tags: %v", rec.Tags)
	}

	// Check review_records.jsonl exists
	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if _, err := os.Stat(jsonlPath); err != nil {
		t.Fatalf("review_records.jsonl not found: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/review/ -v`
Expected: FAIL — `review.RunWithIO` not defined

- [ ] **Step 3: Write the implementation**

```go
// internal/review/run.go
package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config) error {
	return RunWithIO(cfg, os.Stdin, os.Stdout, time.Now())
}

func RunWithIO(cfg config.Config, input io.Reader, output io.Writer, now time.Time) error {
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	packetPaths, err := filepath.Glob(filepath.Join(runfs.ArbiterPacketsDir(cfg.RunDir), "review-*.md"))
	if err != nil {
		return fmt.Errorf("glob review packets: %w", err)
	}

	scanner := bufio.NewScanner(input)
	total := len(findings.Findings)
	var records []artifacts.ReviewRecord

	for idx, item := range findings.Findings {
		// Load corresponding packet text
		var packetText string
		if idx < len(packetPaths) {
			data, err := os.ReadFile(packetPaths[idx])
			if err == nil {
				packetText = string(data)
			}
		}

		DisplayPacketSummary(output, idx, total, item, packetText)

		verdict := PromptVerdict(scanner, output)
		if verdict == "quit" {
			fmt.Fprintln(output, "Review session ended.")
			break
		}
		if verdict == "skip" {
			fmt.Fprintln(output, "Skipped.")
			continue
		}

		severity := PromptSeverityOverride(scanner, output, item.Severity)
		tags := PromptTags(scanner, output)
		notes := PromptNotes(scanner, output)

		record := artifacts.ReviewRecord{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        item.FindingID,
			FindingID:     item.FindingID,
			Verdict:       verdict,
			Severity:      severity,
			Tags:          tags,
			Notes:         notes,
			ReviewedAt:    now.Format(time.RFC3339),
		}
		records = append(records, record)

		// Write individual review file
		reviewPath := filepath.Join(runfs.ReviewDir(cfg.RunDir), fmt.Sprintf("review-%03d.json", idx+1))
		if err := runfs.WriteJSON(reviewPath, record); err != nil {
			return fmt.Errorf("write review %s: %w", record.CaseID, err)
		}
		fmt.Fprintf(output, "✓ Saved review-%03d.json\n", idx+1)
	}

	// Write review_records.jsonl
	if len(records) > 0 {
		jsonlPath := runfs.ReviewRecordsPath(cfg.RunDir)
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open review_records.jsonl: %w", err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("write jsonl record: %w", err)
			}
		}
		fmt.Fprintf(output, "\nWrote %d review record(s) to %s\n", len(records), jsonlPath)
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/review/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/review/
git commit -m "feat(review): add interactive review run loop"
```

---

## Task 10: Feedback Writeback

**Files:**
- Create: `internal/feedback/run.go`
- Create: `internal/feedback/run_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/run_test.go
package feedback_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestFeedbackArchivesAndSuggestsWiki(t *testing.T) {
	runDir := t.TempDir()
	knowledgeRoot := filepath.Join(t.TempDir(), "knowledge")
	if err := knowledge.EnsureLayout(knowledgeRoot); err != nil {
		t.Fatal(err)
	}

	// Write a review_records.jsonl with one confirmed and one dismissed record
	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	records := []artifacts.ReviewRecord{
		{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        "case-001",
			FindingID:     "case-001",
			Verdict:       "confirmed",
			Severity:      "high",
			Tags:          []string{"attestation", "freshness"},
			Notes:         "Real issue confirmed",
			ReviewedAt:    "2026-04-06T12:00:00Z",
		},
		{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        "case-002",
			FindingID:     "case-002",
			Verdict:       "dismissed",
			Severity:      "medium",
			Tags:          []string{"boundary"},
			Notes:         "False alarm",
			ReviewedAt:    "2026-04-06T12:01:00Z",
		},
	}
	f, err := os.Create(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	// Also write a findings.json so feedback can pull context
	findingsData := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-001",
		Findings: []artifacts.FindingItem{
			{FindingID: "case-001", Summary: "Missing attestation freshness", Severity: "high", Status: "confirmed_candidate", Files: []string{"verify.rs"}},
			{FindingID: "case-002", Summary: "Boundary issue", Severity: "medium", Status: "needs_review", Files: []string{"bridge.rs"}},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findingsData); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cfg := config.Config{
		Command:       "feedback",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}
	if err := feedback.Run(cfg, &output); err != nil {
		t.Fatalf("feedback failed: %v", err)
	}

	// Check true-positive archive was created
	tpPath := filepath.Join(knowledgeRoot, "learned", "true-positive", "case-001.md")
	if _, err := os.Stat(tpPath); err != nil {
		t.Fatalf("true-positive archive not found: %v", err)
	}

	// Check false-positive archive was created
	fpPath := filepath.Join(knowledgeRoot, "learned", "false-positive", "case-002.md")
	if _, err := os.Stat(fpPath); err != nil {
		t.Fatalf("false-positive archive not found: %v", err)
	}

	// Check that output mentions wiki suggestion or update
	outStr := output.String()
	if !containsAny(outStr, "wiki", "Suggest", "Appended") {
		t.Fatalf("expected wiki-related output, got: %s", outStr)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/feedback/ -v`
Expected: FAIL — package not found

- [ ] **Step 3: Write the implementation**

```go
// internal/feedback/run.go
package feedback

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func Run(cfg config.Config, w io.Writer) error {
	records, err := loadReviewRecords(runfs.ReviewRecordsPath(cfg.RunDir))
	if err != nil {
		return fmt.Errorf("load review records: %w", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(w, "No review records found.")
		return nil
	}

	// Load findings for context
	findingsMap := make(map[string]artifacts.FindingItem)
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err == nil {
		for _, f := range findings.Findings {
			findingsMap[f.FindingID] = f
		}
	}

	// Load wiki pages for tag matching
	pages, _ := knowledge.LoadPages(cfg.KnowledgeRoot)

	archived := 0
	for _, rec := range records {
		finding := findingsMap[rec.FindingID]

		// Archive to learned/
		if err := archiveRecord(cfg.KnowledgeRoot, rec, finding); err != nil {
			return fmt.Errorf("archive %s: %w", rec.CaseID, err)
		}
		archived++

		// Wiki update suggestions
		suggestWikiUpdates(w, cfg.KnowledgeRoot, rec, pages)
	}

	fmt.Fprintf(w, "\nArchived %d review record(s) to %s/learned/\n", archived, cfg.KnowledgeRoot)
	return nil
}

func loadReviewRecords(path string) ([]artifacts.ReviewRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []artifacts.ReviewRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec artifacts.ReviewRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

func archiveRecord(knowledgeRoot string, rec artifacts.ReviewRecord, finding artifacts.FindingItem) error {
	var subdir string
	switch rec.Verdict {
	case "confirmed":
		subdir = "true-positive"
	case "dismissed":
		subdir = "false-positive"
	default:
		subdir = "review-memory"
	}

	dir := filepath.Join(knowledgeRoot, "learned", subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	content := buildArchivePage(rec, finding)
	target := filepath.Join(dir, sanitizeFilename(rec.CaseID)+".md")
	return os.WriteFile(target, []byte(content), 0o644)
}

func buildArchivePage(rec artifacts.ReviewRecord, finding artifacts.FindingItem) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", rec.CaseID))
	b.WriteString(fmt.Sprintf("- Verdict: %s\n", rec.Verdict))
	b.WriteString(fmt.Sprintf("- Severity: %s\n", rec.Severity))
	if len(rec.Tags) > 0 {
		b.WriteString(fmt.Sprintf("- Tags: %s\n", strings.Join(rec.Tags, ", ")))
	}
	b.WriteString(fmt.Sprintf("- Reviewed: %s\n", rec.ReviewedAt))
	if rec.Notes != "" {
		b.WriteString(fmt.Sprintf("\n## Notes\n\n%s\n", rec.Notes))
	}
	b.WriteString("\n## Context\n\n")
	if finding.Summary != "" {
		b.WriteString(fmt.Sprintf("- Summary: %s\n", finding.Summary))
	}
	if finding.Status != "" {
		b.WriteString(fmt.Sprintf("- Arbiter status: %s\n", finding.Status))
	}
	if len(finding.Files) > 0 {
		b.WriteString(fmt.Sprintf("- Files: %s\n", strings.Join(finding.Files, ", ")))
	}
	return b.String()
}

func suggestWikiUpdates(w io.Writer, knowledgeRoot string, rec artifacts.ReviewRecord, pages []knowledge.Page) {
	if len(rec.Tags) == 0 {
		return
	}
	matched := false
	for _, tag := range rec.Tags {
		for _, page := range pages {
			if tagMatchesPage(tag, page) {
				appendLearnedEntry(knowledgeRoot, page, rec)
				fmt.Fprintf(w, "Appended learned entry to %s for %s\n", page.Path, rec.CaseID)
				matched = true
				break
			}
		}
	}
	if !matched {
		for _, tag := range rec.Tags {
			fmt.Fprintf(w, "Suggest new wiki page: obligations/%s.md (from %s)\n", tag, rec.CaseID)
		}
	}
}

func tagMatchesPage(tag string, page knowledge.Page) bool {
	tag = strings.ToLower(tag)
	if strings.Contains(strings.ToLower(page.Title), tag) {
		return true
	}
	for _, pt := range page.Tags {
		if strings.ToLower(pt) == tag {
			return true
		}
	}
	return false
}

func appendLearnedEntry(knowledgeRoot string, page knowledge.Page, rec artifacts.ReviewRecord) {
	fullPath := filepath.Join(knowledgeRoot, page.Path)
	entry := fmt.Sprintf("\n## Learned\n\n- %s: %s (verdict=%s, severity=%s)\n",
		rec.CaseID, rec.Notes, rec.Verdict, rec.Severity)

	f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(entry)
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "@", "_")
	return r.Replace(s)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/feedback/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/
git commit -m "feat(feedback): add review archival and wiki suggestion writeback"
```

---

## Task 11: Wire Review And Feedback Into main.go

**Files:**
- Modify: `cmd/teecheck/main.go`

- [ ] **Step 1: Add imports and command routing**

Add imports for `review` and `feedback` packages. Add two new cases in the switch:

```go
import (
	// ... existing imports ...
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
)

// In the switch block, add after case "arbiter":
case "review":
	err = review.Run(cfg)
case "feedback":
	err = feedback.Run(cfg, os.Stdout)
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./cmd/teecheck/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add cmd/teecheck/main.go
git commit -m "feat: wire review and feedback commands into CLI"
```

---

## Task 12: Integrate Static Check Registry Into Verifier

**Files:**
- Modify: `internal/verifier/run.go`

- [ ] **Step 1: Refactor buildMemo to accept static check findings**

Replace the hardcoded TODO/FIXME scanning in `buildMemo` with a version that accepts `[]staticcheck.CheckFinding` as input. The caller in `Run()` will create a registry and run the grep adapter (preserving current behavior, but through the adapter framework).

Updated `Run` function:

```go
package verifier

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
)

func Run(cfg config.Config) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	reg := scall.NewDefaultRegistry()
	enabledTools := parseStaticTools(cfg.StaticTools)

	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", casePath, err)
		}
		var hypothesis artifacts.Hypothesis
		if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis: %w", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1)), &challenge); err != nil {
			return fmt.Errorf("read challenge: %w", err)
		}

		// Run static checks
		var scFindings []staticcheck.CheckFinding
		if enabledTools != nil {
			req := staticcheck.CheckRequest{
				RepoRoot:    manifest.LocalPath,
				TargetFiles: pack.TargetFiles,
				Keywords:    append(pack.ExpectedObligations, pack.TargetSymbols...),
				Category:    pack.Category,
			}
			for _, toolName := range enabledTools {
				results, err := reg.RunByName(context.Background(), toolName, req)
				if err != nil {
					fmt.Printf("Warning: static check %s failed: %v\n", toolName, err)
					continue
				}
				scFindings = append(scFindings, results...)
			}
		}

		memo := buildMemo(pack, hypothesis, challenge, cfg.AgentID, scFindings)
		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo %s: %w", memo.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d verification memo(s) to %s\n", count, runfs.VerifierDir(cfg.RunDir))
	return nil
}

func buildMemo(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, agentID string, scFindings []staticcheck.CheckFinding) artifacts.VerificationMemo {
	status := "inconclusive"
	var checks []string
	var confirmed []string
	var contradictions []string

	// Process static check findings
	for _, f := range scFindings {
		checks = append(checks, fmt.Sprintf("%s: %s", f.ToolName, f.RuleID))
		lower := strings.ToLower(f.Message)
		if strings.Contains(lower, "todo") || strings.Contains(lower, "fixme") || strings.Contains(lower, "missing") {
			confirmed = append(confirmed, fmt.Sprintf("%s:%d %s (via %s)", f.Path, f.StartLine, f.Message, f.ToolName))
			status = "corroborated"
		} else if strings.Contains(lower, "bind") || strings.Contains(lower, "caller") || strings.Contains(lower, "authorize") {
			contradictions = append(contradictions, fmt.Sprintf("%s:%d may contain binding logic (via %s)", f.Path, f.StartLine, f.ToolName))
			if status != "corroborated" {
				status = "contested"
			}
		} else if f.Severity == "warning" || f.Severity == "error" {
			confirmed = append(confirmed, fmt.Sprintf("%s:%d %s (via %s)", f.Path, f.StartLine, f.Message, f.ToolName))
			status = "corroborated"
		}
	}

	if len(checks) == 0 {
		checks = append(checks, "no static checks ran")
	}
	if len(confirmed) == 0 && len(contradictions) == 0 {
		contradictions = append(contradictions, "No corroborating evidence found in the bounded files.")
	}

	notes := []string{
		fmt.Sprintf("Static tools used: %s", strings.Join(toolNames(scFindings), ", ")),
	}
	if hypothesis.NeedsVerification {
		notes = append(notes, "Expert explicitly requested follow-up verification.")
	}
	if len(challenge.RemainingQuestions) > 0 {
		notes = append(notes, "Challenger left unresolved questions that may require wrapper-context inspection.")
	}

	return artifacts.VerificationMemo{
		SchemaVersion:  "teecheck.verification_memo.v1",
		CaseID:         pack.CaseID,
		AgentID:        agentID,
		Status:         status,
		ChecksRun:      checks,
		ConfirmedFacts: confirmed,
		Contradictions: contradictions,
		Notes:          notes,
	}
}

func parseStaticTools(value string) []string {
	if value == "" || strings.EqualFold(value, "auto") {
		return []string{"grep"}
	}
	if strings.EqualFold(value, "none") {
		return nil
	}
	var tools []string
	for _, t := range strings.Split(value, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		if t != "" {
			tools = append(tools, t)
		}
	}
	return tools
}

func toolNames(findings []staticcheck.CheckFinding) []string {
	seen := map[string]bool{}
	var names []string
	for _, f := range findings {
		if !seen[f.ToolName] {
			seen[f.ToolName] = true
			names = append(names, f.ToolName)
		}
	}
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
}
```

- [ ] **Step 2: Add StaticTools flag to parseVerifier in config**

In `parseVerifier`, add:

```go
fs.StringVar(&cfg.StaticTools, "static-tools", "auto", "Static tools to enable: auto, none, or comma-separated names")
```

- [ ] **Step 3: Run existing tests to ensure no regression**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./... -v`
Expected: All existing tests pass (the collabrun integration test exercises the full pipeline including the updated verifier)

- [ ] **Step 4: Commit**

```bash
git add internal/verifier/run.go internal/config/config.go
git commit -m "feat(verifier): integrate static check registry into verification"
```

---

## Task 13: Full Integration Test

**Files:**
- Modify: `internal/collabrun/run_test.go`

- [ ] **Step 1: Extend integration test to verify new artifacts work end-to-end**

The existing `TestRunProducesCollaborativeArtifacts` already covers the pipeline through arbiter. Add a new test that simulates the review + feedback flow on top of a collab-run output:

```go
func TestReviewAndFeedbackFlow(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "collab-run",
		RunID:         "feedback-test-001",
		RepoURL:       "https://example.com/sample.git",
		LocalPath:     filepath.Join(root, "testdata", "sample_repo"),
		Commit:        "deadbeefcafebabe",
		Focus:         "runtime",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		GraphJSONPath: filepath.Join(root, "testdata", "sample_graph.json"),
		MaxHotspots:   4,
		MaxCases:      4,
	}

	runDir, err := Run(cfg, time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("collab run failed: %v", err)
	}

	// Simulate interactive review: confirm first case, then quit
	input := "c\n\ntee\nLooks legit\nq\n"
	var output bytes.Buffer
	reviewCfg := config.Config{
		Command:       "review",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}
	if err := review.RunWithIO(reviewCfg, strings.NewReader(input), &output, time.Date(2026, 4, 6, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("review failed: %v", err)
	}

	// Check review output was created
	if _, err := os.Stat(filepath.Join(runfs.ReviewDir(runDir), "review-001.json")); err != nil {
		t.Fatalf("review-001.json not found: %v", err)
	}

	// Run feedback
	var fbOutput bytes.Buffer
	fbCfg := config.Config{
		Command:       "feedback",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}
	if err := feedback.Run(fbCfg, &fbOutput); err != nil {
		t.Fatalf("feedback failed: %v", err)
	}

	// Check that learned/ got an archive file
	matches, _ := filepath.Glob(filepath.Join(knowledgeRoot, "learned", "*", "*.md"))
	if len(matches) == 0 {
		t.Fatal("expected at least one learned archive file")
	}
}
```

Add imports at top of file: `"bytes"`, `"strings"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"`.

- [ ] **Step 2: Run the full test suite**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./... -v`
Expected: All tests pass including the new integration test

- [ ] **Step 3: Commit**

```bash
git add internal/collabrun/run_test.go
git commit -m "test: add integration test for review and feedback flow"
```

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Core static check types | `staticcheck/adapter.go` |
| 2 | Registry | `staticcheck/registry.go` |
| 3 | Grep adapter | `staticcheck/grep/adapter.go` |
| 4 | Semgrep adapter | `staticcheck/semgrep/adapter.go` |
| 5 | CodeQL/Joern stubs + default registry | `staticcheck/codeql/`, `joern/`, `all/` |
| 6 | ReviewRecord type + runfs paths | `artifacts/types.go`, `runfs/paths.go` |
| 7 | Config changes | `config/config.go` |
| 8 | Review display + prompt | `review/display.go`, `review/prompt.go` |
| 9 | Review run loop | `review/run.go` |
| 10 | Feedback writeback | `feedback/run.go` |
| 11 | Wire into main.go | `cmd/teecheck/main.go` |
| 12 | Verifier integration | `verifier/run.go` |
| 13 | Full integration test | `collabrun/run_test.go` |
