package actions_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// The fact layer shells out to git to build the database's source tree.
// That clone used to leave no trace: a run could not say whether it had
// fetched the repository it claimed to have analysed, let alone at which
// revision. These tests drive the whole path — planner action, fact layer,
// REAL git — and assert on what landed in the record.
//
// The CodeQL half is a fake engine (codeql is not installed here, and a
// real database build is minutes of CPU); the git half is real.

func gitInit(t *testing.T) (repo, commit string) {
	t.Helper()
	repo = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet")
	run("config", "user.email", "t@t.invalid")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.c"), []byte("int main(){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "--quiet", "-m", "first")

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return repo, string(out[:40])
}

func TestFactLayerQuery_RecordsItsGitSubprocesses(t *testing.T) {
	repo, commit := gitInit(t)

	// A non-empty fact table is what gets the request past the
	// "unsupported" gate and into the database build, where the clone is.
	trustirfacts.SetFactTable(repo, trustirfacts.FactTable{
		RollbackFields: []string{"version"},
	})
	t.Cleanup(trustirfacts.ResetFactTables)

	h := eventstest.New(t)
	handler := &actions.FactLayerQueryHandler{
		Engine:       &fakeFactEngine{available: true},
		QueryPackDir: t.TempDir(),
	}

	handler.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, string(trustirfacts.OperationRollbackVersionPropagation)),
		RunDir:     t.TempDir(),
		Repository: repo,
		Commit:     commit,
		Executor:   &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs},
		RunID:      "run-99",
		Agent:      "planner-001",
		Round:      4,
	})

	all := h.Events()
	cloneStarted, cloneDone := h.ToolEvents(all, 0)
	coStarted, _ := h.ToolEvents(all, 1)

	if cloneStarted.ToolName != "git-clone" {
		t.Fatalf("first tool call = %q, want git-clone", cloneStarted.ToolName)
	}
	if coStarted.ToolName != "git-checkout" {
		t.Fatalf("second tool call = %q, want git-checkout", coStarted.ToolName)
	}

	// The correlation ids must survive all the way down from the
	// ActionRequest. Without them the events exist but cannot be tied to
	// the round that caused them.
	if cloneStarted.RunID != "run-99" || cloneStarted.Agent != "planner-001" || cloneStarted.Round != 4 {
		t.Errorf("clone event correlation = run=%q agent=%q round=%d, want run-99/planner-001/4",
			cloneStarted.RunID, cloneStarted.Agent, cloneStarted.Round)
	}

	// And the args resolve to the exact command, including the pinned
	// revision — the thing a reader most needs to confirm.
	if got, want := h.Blob(cloneStarted.ToolArgsBlob), "clone\n--quiet\n--\n"+repo; !hasPrefix(got, want) {
		t.Errorf("clone args blob = %q, want it to start with %q", got, want)
	}
	if got := h.Blob(coStarted.ToolArgsBlob); got != "checkout\n--quiet\n"+commit+"\n--" {
		t.Errorf("checkout args blob = %q, want the pinned revision %q", got, commit)
	}
	if !cloneDone.ToolOK {
		t.Errorf("clone tool_ok = false: %+v", cloneDone)
	}
}

// With no executor in the ActionRequest the fact layer must still run its
// git commands and record nothing — the handler must not refuse.
func TestFactLayerQuery_NoExecutorStillClonesAndRecordsNothing(t *testing.T) {
	repo, commit := gitInit(t)
	trustirfacts.SetFactTable(repo, trustirfacts.FactTable{RollbackFields: []string{"version"}})
	t.Cleanup(trustirfacts.ResetFactTables)

	h := eventstest.New(t)
	handler := &actions.FactLayerQueryHandler{
		Engine:       &fakeFactEngine{available: true},
		QueryPackDir: t.TempDir(),
	}

	res := handler.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, string(trustirfacts.OperationRollbackVersionPropagation)),
		RunDir:     t.TempDir(),
		Repository: repo,
		Commit:     commit,
		// Executor deliberately nil.
	})
	if !res.OK {
		t.Fatalf("handler failed without an executor: %+v", res)
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
