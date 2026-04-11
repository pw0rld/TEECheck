# LLM Planner M1 — Artifact Schema + Sandbox + Basic Read Actions

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the foundation for the L3 LLM planner: artifact types, runfs paths, the action contract, a hardened path sandbox, and the three read-only actions (`list_dir`, `read_file`, `ripgrep`), each covered by unit tests. No planner loop yet — actions are testable in isolation.

**Architecture:** New package `internal/planner/actions` containing the `Handler` interface, a sandbox resolver that rejects path escapes and symlinks, and one handler per action. Types for the eventual evidence bundle are added to `internal/artifacts` and new `runfs` paths are added for the `04_planner/` directory. All code is pure Go stdlib + `exec` shell-out for ripgrep (no cgo, no tree-sitter yet — those come in M2).

**Tech Stack:** Go 1.25, stdlib only. `rg` (ripgrep) is an external binary dependency used by the ripgrep action but detected at runtime.

**Spec:** `docs/superpowers/specs/2026-04-11-llm-planner-design.md` — this plan implements Milestone 1.

---

## File Structure

### Files created

| Path | Purpose |
|---|---|
| `internal/planner/actions/types.go` | `ActionRequest`, `ActionResult`, `Handler` interface |
| `internal/planner/actions/sandbox.go` | `ResolvePath` — path normalization + escape rejection + symlink rejection |
| `internal/planner/actions/sandbox_test.go` | Escape / symlink / absolute path rejection tests |
| `internal/planner/actions/list_dir.go` | `ListDirHandler` |
| `internal/planner/actions/list_dir_test.go` | list_dir tests |
| `internal/planner/actions/read_file.go` | `ReadFileHandler` |
| `internal/planner/actions/read_file_test.go` | read_file tests |
| `internal/planner/actions/ripgrep.go` | `RipgrepHandler` |
| `internal/planner/actions/ripgrep_test.go` | ripgrep tests (gated on `rg` availability) |
| `internal/planner/actions/registry.go` | `Registry` with default handler set |
| `internal/planner/actions/registry_test.go` | Registry dispatch / unknown action tests |

### Files modified

| Path | Change |
|---|---|
| `internal/artifacts/types.go` | Add `EvidenceBundle`, `Candidate`, `SinkHit`, `SinkHitSummary`, `PlannerMeta`, `RoundRecord` |
| `internal/runfs/paths.go` | Add `PlannerDir`, `EvidenceBundlePath`, `RoundsLogPath`, `SinkHitsPath` |

### Out of scope for M1

- Planner loop (`planner.go`, `state.go`, `prompt.go`, `budget.go`) → M3
- Sink catalog loader and tree-sitter actions → M2
- `reverse_trace`, `legacy_keyword_scan`, `repomix_summarize`, `sink_catalog_lookup`, `done` actions → M2/M3
- Pipeline integration (scanner/scan.go, cases/run.go, config) → M4

---

## Task 1: Add evidence bundle artifact types

**Files:**
- Modify: `internal/artifacts/types.go` (append at end of file)

- [ ] **Step 1.1: Add the new types**

The existing `internal/artifacts/types.go` has no import block — it starts with `package artifacts` on line 1 followed by type declarations. Add an import for `encoding/json` immediately after `package artifacts`, then append the new types at the end of the file.

After editing, the top of the file should look like:

```go
package artifacts

import "encoding/json"

type Manifest struct {
	// ... existing ...
}
```

Append at the end of the file:

```go
// EvidenceBundle is the top-level output of the L3 LLM planner.
// It is the primary input to the cases stage in --mode llm runs.
type EvidenceBundle struct {
	SchemaVersion  string         `json:"schema_version"`
	RunID          string         `json:"run_id"`
	Repo           RepoRef        `json:"repo"`
	PlannerMeta    PlannerMeta    `json:"planner_meta"`
	Candidates     []Candidate    `json:"candidates"`
	SinksObserved  []SinkHitGroup `json:"sinks_observed,omitempty"`
	ProposedSinks  []ProposedSink `json:"proposed_sinks,omitempty"`
	Errors         []RoundError   `json:"errors,omitempty"`
	FinalSummary   string         `json:"final_summary,omitempty"`
}

type PlannerMeta struct {
	RoundsUsed         int    `json:"rounds_used"`
	RoundsBudget       int    `json:"rounds_budget"`
	TokensUsed         int    `json:"tokens_used"`
	WallClockMs        int64  `json:"wall_clock_ms"`
	TerminationReason  string `json:"termination_reason"`
	Truncated          bool   `json:"truncated"`
}

type Candidate struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Priority     string   `json:"priority"`
	Paths        []string `json:"paths"`
	Symbols      []string `json:"symbols,omitempty"`
	WhySelected  []string `json:"why_selected"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	SinkCategory string   `json:"sink_category,omitempty"`
	Confidence   float64  `json:"confidence,omitempty"`
}

type SinkHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

type SinkHitGroup struct {
	Category string    `json:"category"`
	Hits     []SinkHit `json:"hits"`
}

type ProposedSink struct {
	CategoryIDSuggested string   `json:"category_id_suggested"`
	Rationale           string   `json:"rationale"`
	ExampleSymbols      []string `json:"example_symbols,omitempty"`
}

type RoundError struct {
	Round  int    `json:"round"`
	Action string `json:"action"`
	Error  string `json:"error"`
}

// RoundRecord is written to 04_planner/rounds.jsonl (one per line).
// Not fed back to the LLM; for debugging and post-hoc analysis only.
type RoundRecord struct {
	Round        int             `json:"round"`
	Thought      string          `json:"thought,omitempty"`
	Actions      []RoundAction   `json:"actions"`
	Observations []RoundObservation `json:"observations"`
	TokensIn     int             `json:"tokens_in"`
	TokensOut    int             `json:"tokens_out"`
	WallClockMs  int64           `json:"wall_clock_ms"`
}

type RoundAction struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type RoundObservation struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}
```

If `encoding/json` is not already imported in `types.go`, add it to the import block.

- [ ] **Step 1.2: Verify the file compiles**

Run: `cd tee-usage-scanner && go build ./internal/artifacts/`
Expected: exit 0, no output.

- [ ] **Step 1.3: Verify JSON round-trip with a smoke test**

Create no new test — use the existing artifacts package tests if any, or just run: `cd tee-usage-scanner && go vet ./internal/artifacts/`
Expected: exit 0.

- [ ] **Step 1.4: Commit**

```bash
cd tee-usage-scanner
git add internal/artifacts/types.go
git commit -m "$(cat <<'EOF'
feat(artifacts): add EvidenceBundle and supporting types

Adds types for the L3 LLM planner output: EvidenceBundle, Candidate,
PlannerMeta, SinkHit, SinkHitGroup, ProposedSink, RoundRecord,
RoundAction, RoundObservation. Schema version is
teecheck.evidence_bundle.v1. These feed the cases stage when running
in --mode llm.

Part of M1 of the planner rework. See
docs/superpowers/specs/2026-04-11-llm-planner-design.md section 6.1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add runfs paths for 04_planner/

**Files:**
- Modify: `internal/runfs/paths.go`

- [ ] **Step 2.1: Add the four new path helpers**

Append to `internal/runfs/paths.go` just before `LoadManifest`:

```go
func PlannerDir(runDir string) string {
	return filepath.Join(runDir, "04_planner")
}

func EvidenceBundlePath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "evidence_bundle.json")
}

func RoundsLogPath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "rounds.jsonl")
}

func SinkHitsPath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "sink_hits.json")
}
```

- [ ] **Step 2.2: Verify compilation**

Run: `cd tee-usage-scanner && go build ./internal/runfs/`
Expected: exit 0.

- [ ] **Step 2.3: Commit**

```bash
cd tee-usage-scanner
git add internal/runfs/paths.go
git commit -m "$(cat <<'EOF'
feat(runfs): add 04_planner directory path helpers

Adds PlannerDir, EvidenceBundlePath, RoundsLogPath, and SinkHitsPath
for the new L3 planner output directory.

Part of M1. See spec section 6.4.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Action contract types

**Files:**
- Create: `internal/planner/actions/types.go`

- [ ] **Step 3.1: Write the types file**

Create `internal/planner/actions/types.go`:

```go
// Package actions defines the planner action contract and the built-in
// handlers the LLM planner dispatches to during reconnaissance.
//
// An Action is a single tool invocation the LLM requests. The registry
// receives ActionRequests and returns ActionResults. Handlers parse their
// own typed arguments from the raw JSON in ActionRequest.Args.
package actions

import (
	"context"
	"encoding/json"
)

// ActionRequest is one tool invocation the LLM has asked for.
type ActionRequest struct {
	// Name identifies which handler to dispatch to.
	Name string `json:"name"`
	// Args is the raw JSON payload the LLM provided.
	// Each handler is responsible for unmarshalling this into its own
	// typed argument struct and validating it.
	Args json.RawMessage `json:"args"`
	// RepoRoot is the absolute path to the cloned repository. It is
	// injected by the planner, not supplied by the LLM.
	RepoRoot string `json:"-"`
}

// ActionResult is what a handler returns. It is the single observation
// format the LLM sees back.
type ActionResult struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Handler is the contract for a single planner action.
//
// Handlers must be safe to run concurrently, must honor ctx cancellation,
// and must never return an error via the Go error channel — all failures
// are reported through ActionResult.OK=false + Error so that the planner
// LLM can observe and react to them.
type Handler interface {
	Name() string
	Run(ctx context.Context, req ActionRequest) ActionResult
}

// fail is a helper for handlers to construct an error result.
func fail(name, msg string) ActionResult {
	return ActionResult{Name: name, OK: false, Error: msg}
}
```

- [ ] **Step 3.2: Verify compilation**

Run: `cd tee-usage-scanner && go build ./internal/planner/actions/`
Expected: exit 0.

- [ ] **Step 3.3: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/types.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add action contract types

Defines ActionRequest, ActionResult, and the Handler interface that
every planner action must implement. Handlers report all failures via
ActionResult.OK=false instead of Go errors so the planner LLM can
observe and react to them.

Part of M1. See spec section 4.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Path sandbox — tests first

The sandbox is the single security-critical piece of M1. Tests come before implementation and are deliberately exhaustive.

**Files:**
- Create: `internal/planner/actions/sandbox_test.go`
- Create: `internal/planner/actions/sandbox.go` (after tests fail)

- [ ] **Step 4.1: Write the sandbox test suite**

Create `internal/planner/actions/sandbox_test.go`:

```go
package actions_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func TestResolvePath_AcceptsRelativeInsideRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := actions.ResolvePath(dir, "a.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, "a.txt")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolvePath_AcceptsCurrentDir(t *testing.T) {
	dir := t.TempDir()
	got, err := actions.ResolvePath(dir, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Accept either the cleaned root or root+"."
	if !strings.HasPrefix(got, dir) {
		t.Fatalf("got %q, want prefix %q", got, dir)
	}
}

func TestResolvePath_RejectsDotDotEscape(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "../secret")
	if err == nil {
		t.Fatal("expected error for ../secret, got nil")
	}
	if !strings.Contains(err.Error(), "escape") {
		t.Fatalf("expected escape error, got %v", err)
	}
}

func TestResolvePath_RejectsEmbeddedDotDot(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "subdir/../../outside")
	if err == nil {
		t.Fatal("expected error for subdir/../../outside, got nil")
	}
}

func TestResolvePath_RejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()

	_, err := actions.ResolvePath(dir, "/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestResolvePath_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test uses POSIX semantics")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Join(outside, "target.txt"), linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := actions.ResolvePath(dir, "link.txt")
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestResolvePath_RejectsSymlinkInAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test uses POSIX semantics")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "child", "target.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make a symlinked subdirectory inside dir pointing outside.
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := actions.ResolvePath(dir, "linkdir/child/target.txt")
	if err == nil {
		t.Fatal("expected error for path whose ancestor is a symlink, got nil")
	}
}

func TestResolvePath_AllowsNonExistentPath(t *testing.T) {
	// Actions like ripgrep may pass paths that do not exist yet;
	// sandbox should not require existence, only reject escape/symlink.
	dir := t.TempDir()

	got, err := actions.ResolvePath(dir, "does/not/exist.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, "does", "not", "exist.txt")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 4.2: Run tests to confirm they fail (compile error)**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestResolvePath -v`
Expected: compile error — `undefined: actions.ResolvePath`.

- [ ] **Step 4.3: Implement sandbox.go to make the tests pass**

Create `internal/planner/actions/sandbox.go`:

```go
package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolvePath normalizes a repo-relative path and guarantees:
//
//  1. The path does not escape repoRoot (no absolute paths, no leading/embedded "..").
//  2. No ancestor directory between repoRoot and the resolved target is a symbolic link.
//  3. If the final target itself exists, it is not a symbolic link.
//
// It does NOT require the target to exist — non-existent paths are allowed
// through so that actions like ripgrep can pass include patterns that do
// not correspond to real files. Callers handle not-found errors themselves.
//
// The returned path is an absolute path rooted at repoRoot.
func ResolvePath(repoRoot, rel string) (string, error) {
	if rel == "" {
		rel = "."
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed: %s", rel)
	}
	cleaned := filepath.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repo root: %s", rel)
	}

	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repo root: %w", err)
	}
	full := filepath.Join(absRoot, cleaned)
	if !strings.HasPrefix(full+string(filepath.Separator), absRoot+string(filepath.Separator)) && full != absRoot {
		return "", fmt.Errorf("path escapes repo root: %s", rel)
	}

	// Walk every ancestor component from absRoot down to full and reject
	// any that is a symlink. Non-existent components are allowed — we
	// stop walking at the first missing one.
	if cleaned != "." {
		current := absRoot
		parts := strings.Split(cleaned, string(filepath.Separator))
		for _, part := range parts {
			if part == "" || part == "." {
				continue
			}
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				if os.IsNotExist(err) {
					break
				}
				return "", fmt.Errorf("lstat %s: %w", current, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlink not allowed: %s", part)
			}
		}
	}

	return full, nil
}
```

- [ ] **Step 4.4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestResolvePath -v`
Expected: all 8 tests PASS.

- [ ] **Step 4.5: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/sandbox.go internal/planner/actions/sandbox_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add path sandbox with escape and symlink rejection

Adds ResolvePath which normalizes a repo-relative path and guarantees
the result stays inside the repo root, rejects absolute paths, rejects
embedded/leading "..", and rejects any symlink in the ancestor chain
including the final target. Non-existent paths are allowed through so
actions that take include patterns (ripgrep) do not have to pre-check.

Tests cover: accept relative, accept ".", reject "../", reject embedded
"..", reject absolute, reject symlink target, reject symlinked ancestor,
allow non-existent.

Part of M1. See spec section 4.1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: list_dir action

**Files:**
- Create: `internal/planner/actions/list_dir_test.go`
- Create: `internal/planner/actions/list_dir.go`

- [ ] **Step 5.1: Write the list_dir tests**

Create `internal/planner/actions/list_dir_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func listDirArgs(t *testing.T, path string, depth int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path, "depth": depth})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestListDir_HappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.rs"), "fn a() {}")
	writeFile(t, filepath.Join(dir, "sub", "b.rs"), "fn b() {}")

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 2),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "sub") {
		t.Fatalf("expected sub in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "b.rs") {
		t.Fatalf("expected b.rs in output, got: %s", result.Output)
	}
}

func TestListDir_DepthZero(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.rs"), "")
	writeFile(t, filepath.Join(dir, "sub", "b.rs"), "")

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 0),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "b.rs") {
		t.Fatalf("depth=0 should not descend into sub, got: %s", result.Output)
	}
}

func TestListDir_DepthCappedAtThree(t *testing.T) {
	dir := t.TempDir()
	// Create a 5-level-deep tree; with depth cap 3 only levels 1..3 should appear.
	deep := filepath.Join(dir, "l1", "l2", "l3", "l4", "l5")
	writeFile(t, filepath.Join(deep, "leaf.rs"), "")

	h := actions.ListDirHandler{}
	// Request depth=99; sandbox should cap to 3.
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 99),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "l3") {
		t.Fatalf("expected l3 in output, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "l5") {
		t.Fatalf("depth should cap at 3, but found l5: %s", result.Output)
	}
}

func TestListDir_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, "../../etc", 1),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
	if !strings.Contains(result.Error, "escape") {
		t.Fatalf("expected escape error, got: %s", result.Error)
	}
}

func TestListDir_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage("not json"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for invalid json")
	}
	if !strings.Contains(result.Error, "invalid args") {
		t.Fatalf("expected invalid args error, got: %s", result.Error)
	}
}
```

- [ ] **Step 5.2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestListDir -v`
Expected: compile error — `undefined: actions.ListDirHandler`.

- [ ] **Step 5.3: Implement list_dir.go**

Create `internal/planner/actions/list_dir.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const listDirMaxDepth = 3

type listDirArgs struct {
	Path  string `json:"path"`
	Depth int    `json:"depth"`
}

// ListDirHandler implements the list_dir action — a recursive directory
// listing bounded by a depth cap of 3.
type ListDirHandler struct{}

func (ListDirHandler) Name() string { return "list_dir" }

func (ListDirHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args listDirArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("list_dir", fmt.Sprintf("invalid args: %v", err))
	}
	if args.Path == "" {
		args.Path = "."
	}
	if args.Depth < 0 {
		args.Depth = 0
	}
	if args.Depth > listDirMaxDepth {
		args.Depth = listDirMaxDepth
	}

	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("list_dir", err.Error())
	}

	info, err := os.Stat(full)
	if err != nil {
		return fail("list_dir", err.Error())
	}
	if !info.IsDir() {
		return fail("list_dir", fmt.Sprintf("%s is not a directory", args.Path))
	}

	var buf strings.Builder
	if err := walkDir(ctx, full, 0, args.Depth, &buf); err != nil {
		return fail("list_dir", err.Error())
	}
	return ActionResult{Name: "list_dir", OK: true, Output: buf.String()}
}

func walkDir(ctx context.Context, dir string, depth, maxDepth int, buf *strings.Builder) error {
	if depth > maxDepth {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	indent := strings.Repeat("  ", depth)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			fmt.Fprintf(buf, "%s%s/\n", indent, name)
			if depth < maxDepth {
				if err := walkDir(ctx, filepath.Join(dir, name), depth+1, maxDepth, buf); err != nil {
					return err
				}
			}
		} else {
			fmt.Fprintf(buf, "%s%s\n", indent, name)
		}
	}
	return nil
}
```

- [ ] **Step 5.4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestListDir -v`
Expected: all 5 tests PASS.

- [ ] **Step 5.5: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/list_dir.go internal/planner/actions/list_dir_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add list_dir action

Recursive directory listing with depth cap (3) and dotfile filtering.
Uses sandbox ResolvePath so escape and symlink paths are rejected
before walking. Depth > 3 is silently capped; depth = 0 lists only
the target directory's direct entries.

Tests cover happy path, depth=0, depth cap, escape rejection, and
invalid-json arg rejection.

Part of M1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: read_file action

**Files:**
- Create: `internal/planner/actions/read_file_test.go`
- Create: `internal/planner/actions/read_file.go`

- [ ] **Step 6.1: Write read_file tests**

Create `internal/planner/actions/read_file_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func readFileArgs(t *testing.T, path string, start, end int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path, "start": start, "end": end})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadFile_FullSmallFile(t *testing.T) {
	dir := t.TempDir()
	content := "line 1\nline 2\nline 3\n"
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "f.txt", 1, 10),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "1: line 1") {
		t.Fatalf("expected line 1 prefix, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3: line 3") {
		t.Fatalf("expected line 3 prefix, got: %s", result.Output)
	}
}

func TestReadFile_PartialRange(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 1; i <= 100; i++ {
		lines = append(lines, strings.Repeat("x", 5))
	}
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "big.txt", 10, 12),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "10:") || !strings.Contains(result.Output, "12:") {
		t.Fatalf("expected lines 10..12, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "9:") || strings.Contains(result.Output, "13:") {
		t.Fatalf("expected only lines 10..12, got extras: %s", result.Output)
	}
}

func TestReadFile_LineCapEnforced(t *testing.T) {
	dir := t.TempDir()
	// 1000 lines
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("x\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "huge.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	// Request entire file; cap should limit to 500 lines.
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "huge.txt", 1, 0),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !result.Truncated {
		t.Fatal("expected truncated=true")
	}
	// Count lines in output; each output line starts with "N: ".
	lineCount := strings.Count(result.Output, "\n")
	if lineCount > 500 {
		t.Fatalf("expected <=500 lines, got %d", lineCount)
	}
	if lineCount < 500 {
		t.Fatalf("expected 500 lines at cap, got %d", lineCount)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	dir := t.TempDir()

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "nope.txt", 1, 10),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for missing file")
	}
}

func TestReadFile_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "../secret.txt", 1, 10),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}
```

- [ ] **Step 6.2: Run tests, confirm compile failure**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestReadFile -v`
Expected: compile error — `undefined: actions.ReadFileHandler`.

- [ ] **Step 6.3: Implement read_file.go**

Create `internal/planner/actions/read_file.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const readFileLineCap = 500

type readFileArgs struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// ReadFileHandler implements the read_file action.
//
// Start and End are 1-indexed, inclusive. If End is 0 or negative, the
// handler reads up to the cap (500) starting from Start. Output is
// prefixed with line numbers so the LLM can reference lines back.
type ReadFileHandler struct{}

func (ReadFileHandler) Name() string { return "read_file" }

func (ReadFileHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args readFileArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("read_file", fmt.Sprintf("invalid args: %v", err))
	}
	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("read_file", err.Error())
	}
	info, err := os.Stat(full)
	if err != nil {
		return fail("read_file", err.Error())
	}
	if info.IsDir() {
		return fail("read_file", fmt.Sprintf("%s is a directory", args.Path))
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return fail("read_file", err.Error())
	}
	lines := strings.Split(string(data), "\n")
	// If the file ended with a trailing newline, drop the empty final element.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if args.Start <= 0 {
		args.Start = 1
	}
	if args.End <= 0 {
		args.End = args.Start + readFileLineCap - 1
	}
	if args.End-args.Start+1 > readFileLineCap {
		args.End = args.Start + readFileLineCap - 1
	}

	if args.Start > len(lines) {
		return fail("read_file", fmt.Sprintf("start line %d beyond file end (%d)", args.Start, len(lines)))
	}
	if args.End > len(lines) {
		args.End = len(lines)
	}

	var buf strings.Builder
	for i := args.Start - 1; i < args.End; i++ {
		fmt.Fprintf(&buf, "%d: %s\n", i+1, lines[i])
	}

	truncated := (args.End - args.Start + 1) < len(lines)
	return ActionResult{Name: "read_file", OK: true, Output: buf.String(), Truncated: truncated}
}
```

- [ ] **Step 6.4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestReadFile -v`
Expected: all 5 tests PASS.

- [ ] **Step 6.5: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/read_file.go internal/planner/actions/read_file_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add read_file action

Line-number-prefixed read with a 500 line per-call cap. Uses sandbox
ResolvePath for escape/symlink rejection. End=0 means "read up to cap
starting at start". Truncation is reported in the result so the planner
LLM can decide whether to request the next range.

Tests cover full small file, partial range, cap enforcement on large
file, not-found, and escape rejection.

Part of M1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: ripgrep action

**Files:**
- Create: `internal/planner/actions/ripgrep_test.go`
- Create: `internal/planner/actions/ripgrep.go`

- [ ] **Step 7.1: Write ripgrep tests**

Create `internal/planner/actions/ripgrep_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func requireRipgrep(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not installed; skipping ripgrep action tests")
	}
}

func ripgrepArgs(t *testing.T, pattern string, globs []string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pattern": pattern, "globs": globs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRipgrep_FindsPattern(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\nfn other() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", nil),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("expected match, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected filename in output, got: %s", result.Output)
	}
}

func TestRipgrep_NoMatch(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn other() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", nil),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK on no-match, got error: %s", result.Error)
	}
	if strings.TrimSpace(result.Output) != "" {
		t.Fatalf("expected empty output, got: %s", result.Output)
	}
}

func TestRipgrep_GlobFilter(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("verify_quote\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.md"), []byte("verify_quote\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", []string{"*.rs"}),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs match, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "b.md") {
		t.Fatalf("glob filter should exclude b.md, got: %s", result.Output)
	}
}

func TestRipgrep_Truncation(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	// 300 matches across one file; cap is 200.
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("verify_quote_target\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote_target", nil),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !result.Truncated {
		t.Fatal("expected truncated=true for >200 matches")
	}
	got := strings.Count(result.Output, "\n")
	if got > 200 {
		t.Fatalf("expected <=200 lines after truncation, got %d", got)
	}
}

func TestRipgrep_MissingPattern(t *testing.T) {
	dir := t.TempDir()

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "", nil),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for empty pattern")
	}
	if !strings.Contains(result.Error, "pattern") {
		t.Fatalf("expected pattern error, got: %s", result.Error)
	}
}
```

- [ ] **Step 7.2: Run tests, confirm compile failure**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestRipgrep -v`
Expected: compile error — `undefined: actions.RipgrepHandler`.

- [ ] **Step 7.3: Implement ripgrep.go**

Create `internal/planner/actions/ripgrep.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const ripgrepMaxMatchLines = 200

type ripgrepArgs struct {
	Pattern string   `json:"pattern"`
	Globs   []string `json:"globs"`
}

// RipgrepHandler implements the ripgrep action. It shells out to `rg`
// with --line-number --no-heading --color=never, passes the repo root
// as the search target, and caps output at ripgrepMaxMatchLines.
//
// Pattern is passed to rg as a separate argv element, never concatenated
// into a shell command, so pattern injection is not possible.
type RipgrepHandler struct{}

func (RipgrepHandler) Name() string { return "ripgrep" }

func (RipgrepHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args ripgrepArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("ripgrep", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Pattern) == "" {
		return fail("ripgrep", "pattern is required")
	}
	if _, err := exec.LookPath("rg"); err != nil {
		return fail("ripgrep", "ripgrep (rg) not installed")
	}

	cmdArgs := []string{"--line-number", "--no-heading", "--color=never"}
	for _, g := range args.Globs {
		if strings.TrimSpace(g) == "" {
			continue
		}
		cmdArgs = append(cmdArgs, "--glob", g)
	}
	cmdArgs = append(cmdArgs, "--", args.Pattern, req.RepoRoot)

	cmd := exec.CommandContext(ctx, "rg", cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			// rg exits 1 on "no matches" — not an error for us.
			return ActionResult{Name: "ripgrep", OK: true, Output: ""}
		}
		return fail("ripgrep", fmt.Sprintf("ripgrep exec: %v", err))
	}

	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return ActionResult{Name: "ripgrep", OK: true, Output: ""}
	}
	lines := strings.Split(text, "\n")
	truncated := false
	if len(lines) > ripgrepMaxMatchLines {
		lines = lines[:ripgrepMaxMatchLines]
		truncated = true
	}
	return ActionResult{
		Name:      "ripgrep",
		OK:        true,
		Output:    strings.Join(lines, "\n"),
		Truncated: truncated,
	}
}
```

- [ ] **Step 7.4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestRipgrep -v`
Expected: all 5 tests PASS (or skipped if `rg` not installed — that is acceptable; TestRipgrep_MissingPattern should still PASS because it fails before rg lookup).

Verify ripgrep is available: `which rg`. If not installed:
- Linux: `apt-get install ripgrep` or `dnf install ripgrep`
- macOS: `brew install ripgrep`

- [ ] **Step 7.5: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/ripgrep.go internal/planner/actions/ripgrep_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add ripgrep action

Shells out to rg with --line-number --no-heading --color=never, caps
output at 200 match lines, and reports truncation. Pattern is passed
as a separate argv element so pattern injection is not possible.
Missing rg binary is reported cleanly via ActionResult.Error so the
LLM can fall back to another action.

Exit code 1 from rg ("no matches") is mapped to OK=true with empty
output. Exit code >1 is mapped to OK=false.

Tests cover match, no-match, glob filter, truncation, empty pattern.

Part of M1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Action registry

**Files:**
- Create: `internal/planner/actions/registry.go`
- Create: `internal/planner/actions/registry_test.go`

- [ ] **Step 8.1: Write the registry tests**

Create `internal/planner/actions/registry_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func TestRegistry_DispatchesKnownAction(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn a() {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": ".", "depth": 1}`),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs in output, got: %s", result.Output)
	}
}

func TestRegistry_UnknownAction(t *testing.T) {
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "nonexistent",
		Args:     json.RawMessage("{}"),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure for unknown action")
	}
	if !strings.Contains(result.Error, "unknown action") {
		t.Fatalf("expected unknown action error, got: %s", result.Error)
	}
}

func TestRegistry_DurationRecorded(t *testing.T) {
	dir := t.TempDir()
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": ".", "depth": 0}`),
		RepoRoot: dir,
	})
	if result.DurationMs < 0 {
		t.Fatalf("expected non-negative duration, got %d", result.DurationMs)
	}
}

func TestRegistry_NameIsBackfilled(t *testing.T) {
	// Registry must stamp the result Name even if a handler forgets to.
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": "."}`),
		RepoRoot: t.TempDir(),
	})
	if result.Name != "list_dir" {
		t.Fatalf("expected name=list_dir, got %s", result.Name)
	}
}

func TestRegistry_ListsRegisteredActions(t *testing.T) {
	reg := actions.NewDefaultRegistry()
	names := reg.Names()
	want := map[string]bool{"list_dir": true, "read_file": true, "ripgrep": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Fatalf("registry missing handlers: %v", want)
	}
}
```

- [ ] **Step 8.2: Run tests, confirm compile failure**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestRegistry -v`
Expected: compile error — `undefined: actions.NewDefaultRegistry`.

- [ ] **Step 8.3: Implement registry.go**

Create `internal/planner/actions/registry.go`:

```go
package actions

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Registry dispatches ActionRequests to the registered Handler.
// It is safe for concurrent use after construction.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: map[string]Handler{}}
}

// NewDefaultRegistry returns a registry pre-populated with the M1
// built-in handlers: list_dir, read_file, ripgrep. Further handlers
// (tree_sitter_outline, reverse_trace, etc.) will be added in later
// milestones.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(ListDirHandler{})
	r.Register(ReadFileHandler{})
	r.Register(RipgrepHandler{})
	return r
}

// Register adds a handler to the registry. If a handler with the same
// name is already present it is overwritten.
func (r *Registry) Register(h Handler) {
	r.handlers[h.Name()] = h
}

// Names returns the sorted list of registered handler names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Run dispatches a single ActionRequest to its handler. Unknown actions
// are reported as OK=false with an "unknown action" error — they do not
// consume a round or propagate up as Go errors.
//
// Run stamps result.Name (in case the handler forgot) and records
// DurationMs.
func (r *Registry) Run(ctx context.Context, req ActionRequest) ActionResult {
	h, ok := r.handlers[req.Name]
	if !ok {
		return ActionResult{
			Name:  req.Name,
			OK:    false,
			Error: fmt.Sprintf("unknown action: %s", req.Name),
		}
	}
	start := time.Now()
	result := h.Run(ctx, req)
	if result.Name == "" {
		result.Name = req.Name
	}
	if result.DurationMs == 0 {
		result.DurationMs = time.Since(start).Milliseconds()
	}
	return result
}
```

- [ ] **Step 8.4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestRegistry -v`
Expected: all 5 tests PASS.

- [ ] **Step 8.5: Commit**

```bash
cd tee-usage-scanner
git add internal/planner/actions/registry.go internal/planner/actions/registry_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add action registry and NewDefaultRegistry

Registry maps action names to handlers and dispatches ActionRequests.
NewDefaultRegistry returns a registry pre-populated with the M1
handlers (list_dir, read_file, ripgrep). Unknown actions are reported
as OK=false with "unknown action" rather than propagated as Go errors
so the planner LLM can observe and recover from typos.

Registry stamps result.Name if the handler forgot it and records
DurationMs for every invocation.

Part of M1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Full-package test sweep

**Files:** None — verification only.

- [ ] **Step 9.1: Run all M1 package tests**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -v`
Expected: all tests in the package PASS (ripgrep tests may SKIP if `rg` not installed).

- [ ] **Step 9.2: Run the full project test suite to check for regressions**

Run: `cd tee-usage-scanner && go test ./...`
Expected: no new failures beyond any pre-existing flaky tests. If any pre-existing failures appear that are unrelated to M1 changes, document them but do not attempt to fix.

- [ ] **Step 9.3: Run go vet on the whole project**

Run: `cd tee-usage-scanner && go vet ./...`
Expected: exit 0.

- [ ] **Step 9.4: Verify binary still builds**

Run: `cd tee-usage-scanner && go build -o /tmp/teecheck-m1 ./cmd/teecheck/`
Expected: exit 0, binary produced. No commit needed — this is a smoke check.

- [ ] **Step 9.5: If all green, mark M1 complete**

Reply: "M1 complete. Ready for M2 planning."

---

## Post-M1

After M1 lands, request an M2 plan covering:
- `knowledge/sinks/rust.json` seed content (3 groups × 13 categories)
- `internal/planner/sinks/{loader,matcher}.go` — catalog loader + syntax/symbol matcher
- `internal/planner/actions/tree_sitter_outline.go` — tree-sitter Rust outline
- `internal/planner/actions/sink_catalog_lookup.go` — catalog lookup action with three scope levels

M2 is the highest technical risk milestone because of the `go-tree-sitter` cgo dependency. Plan it after confirming local Go + cgo + Rust grammar binding builds successfully on the target platform.
