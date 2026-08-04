package actions_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// gitInit builds a throwaway local repository with one commit, for tests
// that need a real repository identity to drive the fact layer with.
//
// This file used to hold two tests asserting that a fact_layer_query
// action's own git clone and checkout were recorded with the planner round's
// correlation ids. That behaviour is gone by design: internal/codedb owns
// the checkout and the pipeline acquires it before the first stage, so by
// the time a planner round asks for a fact the tree is already there and no
// git subprocess runs inside the action at all.
//
// The clone's own recording is covered where the clone now lives —
// internal/codedb/clone_recording_test.go. What was lost is the attribution
// of that clone to a planner round, which is correct: acquiring the
// repository is not the planner's work.
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

// The two tests that lived here asserted that a fact_layer_query action's
// own git clone and checkout were recorded with the planner round's
// correlation ids. That behaviour is gone by design: internal/codedb owns
// the checkout and the pipeline acquires it before the first stage, so by
// the time a planner round asks for a fact the tree is already there and no
// git subprocess runs inside the action at all.
//
// The clone's own recording is covered where the clone now lives —
// internal/codedb/clone_recording_test.go. What was lost is the attribution
// of that clone to a planner round, which is correct: acquiring the
// repository is not the planner's work.
