package trustirfacts

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// git IS installed here, so unlike the semgrep / codeql / repomix
// recording tests these exercise the real binary end to end: a real clone
// of a real repository, recorded into a real events.jsonl.

func newOrigin(t *testing.T) (dir, firstCommit string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "--quiet")
	git(t, dir, "config", "user.email", "test@test.com")
	git(t, dir, "config", "user.name", "test")
	writeAndCommit(t, dir, "version.txt", "v1\n", "first commit")
	firstCommit = headCommit(t, dir)
	writeAndCommit(t, dir, "version.txt", "v2\n", "second commit")
	return dir, firstCommit
}

// Both git invocations — clone and checkout — must leave a pair, with args
// resolving to the exact argv.
func TestRecordsCloneAndCheckout(t *testing.T) {
	origin, first := newOrigin(t)
	dest := filepath.Join(t.TempDir(), "checkout")
	h := eventstest.New(t)

	ex := &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}
	if err := cloneAtRevision(context.Background(), ex, origin, first, dest); err != nil {
		t.Fatalf("cloneAtRevision: %v", err)
	}

	all := h.Events()
	cloneStarted, cloneDone := h.ToolEvents(all, 0)
	coStarted, coDone := h.ToolEvents(all, 1)

	if cloneStarted.ToolName != "git-clone" {
		t.Errorf("tool_name = %q, want git-clone", cloneStarted.ToolName)
	}
	wantClone := strings.Join([]string{"clone", "--quiet", "--", origin, dest}, "\n")
	if got := h.Blob(cloneStarted.ToolArgsBlob); got != wantClone {
		t.Errorf("clone args blob =\n%q\nwant\n%q", got, wantClone)
	}
	if !cloneDone.ToolOK {
		t.Errorf("clone tool_ok = false: %+v", cloneDone)
	}

	if coStarted.ToolName != "git-checkout" {
		t.Errorf("tool_name = %q, want git-checkout", coStarted.ToolName)
	}
	wantCheckout := strings.Join([]string{"checkout", "--quiet", first, "--"}, "\n")
	if got := h.Blob(coStarted.ToolArgsBlob); got != wantCheckout {
		t.Errorf("checkout args blob =\n%q\nwant\n%q", got, wantCheckout)
	}
	if !coDone.ToolOK {
		t.Errorf("checkout tool_ok = false: %+v", coDone)
	}
}

// A failing git must record what it said. git writes its diagnostics to
// stderr, so a record that dropped stderr would be worthless here.
func TestRecordsFailingClone(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	dest := filepath.Join(t.TempDir(), "checkout")
	h := eventstest.New(t)

	ex := &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}
	err := cloneAtRevision(context.Background(), ex, missing, "HEAD", dest)
	if err == nil {
		t.Fatal("expected an error")
	}

	all := h.Events()
	_, completed := h.ToolEvents(all, 0)
	if completed.ToolOK {
		t.Error("tool_ok = true on a failed clone")
	}
	if completed.ToolExitCode == 0 {
		t.Error("tool_exit_code = 0 on a failed clone")
	}
	stderr := h.Blob(completed.ToolStderrBlob)
	if !strings.Contains(stderr, missing) {
		t.Errorf("stderr blob = %q, want it to name the repository git could not open", stderr)
	}
	// The checkout must not have been attempted.
	for _, e := range all {
		if e.ToolName == "git-checkout" {
			t.Error("checkout ran after the clone failed")
		}
	}
}

// The injection guards fire before git is ever invoked, so a rejected
// request must leave NO tool call in the record at all — otherwise the
// stream would claim a command ran that never did.
func TestRejectedArgsRecordNothing(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "checkout")
	h := eventstest.New(t)
	ex := &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	if err := cloneAtRevision(context.Background(), ex, "ext::sh -c :", "HEAD", dest); err == nil {
		t.Fatal("expected rejection")
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s for a call that was rejected before exec", e.Type)
		}
	}
}

func TestNoExecutorStillWorksAndRecordsNothing(t *testing.T) {
	origin, first := newOrigin(t)
	dest := filepath.Join(t.TempDir(), "checkout")
	h := eventstest.New(t)

	if err := cloneAtRevision(context.Background(), nil, origin, first, dest); err != nil {
		t.Fatalf("cloneAtRevision with no executor: %v", err)
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
}

// Request.Exec is the seam the planner action wires. It must not change
// the request's identity: the fact ID and the database cache key are
// derived from repository+commit+operation only, and a run that suddenly
// recorded its subprocesses must still hit the same cache.
func TestExecDoesNotAffectRequestIdentity(t *testing.T) {
	base := Request{
		RunDir: "/run", Repository: "https://example.invalid/r", Commit: "abc123",
		Operation: OperationRollbackVersionPropagation, QueryPackDir: "/pack",
	}
	withExec := base
	withExec.Exec = &executor.LocalExecutor{}

	if base.argumentsSHA256() != withExec.argumentsSHA256() {
		t.Error("arguments hash changed when an executor was wired in")
	}
	if base.factID() != withExec.factID() {
		t.Error("fact ID changed when an executor was wired in")
	}
}
