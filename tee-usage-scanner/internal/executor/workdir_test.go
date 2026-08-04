package executor

import (
	"context"
	"strings"
	"testing"
)

// The executor is the one place every subprocess in this system passes
// through, so "a path crossing a process boundary must be absolute" belongs
// here rather than in each tool's comments.
//
// A relative working directory is resolved twice: once as cmd.Dir, and again
// by any tool handed the same path as an argument. ripgrep is given its
// search root both ways, so a relative root made it cd into the tree and
// then look for the tree inside itself. Across p11, run-a and run-b all 17
// of its calls returned "No such file or directory" while read_file in the
// same round succeeded — and nothing surfaced it.
func TestLocalExecutor_RejectsARelativeWorkDir(t *testing.T) {
	res := (&LocalExecutor{}).Run(context.Background(), Request{
		Name:    "ripgrep",
		Command: "echo",
		Args:    []string{"hi"},
		WorkDir: "runs/run-b/02_tool_facts/trustir/src/df16a35b",
	})
	if res.Error == "" {
		t.Fatal("a relative work dir must be refused, not run")
	}
	if !strings.Contains(res.Error, "absolute") {
		t.Errorf("the error must say what is wrong with it: %q", res.Error)
	}
	if res.ExitCode == 0 && len(res.Stdout) > 0 {
		t.Errorf("the command must not have run: %+v", res)
	}
}

// An absolute work dir is the normal case and must be untouched.
func TestLocalExecutor_AcceptsAnAbsoluteWorkDir(t *testing.T) {
	res := (&LocalExecutor{}).Run(context.Background(), Request{
		Name: "echo", Command: "echo", Args: []string{"hi"}, WorkDir: t.TempDir(),
	})
	if res.Error != "" {
		t.Fatalf("an absolute work dir must be accepted: %s", res.Error)
	}
	if !strings.Contains(string(res.Stdout), "hi") {
		t.Errorf("stdout = %q, want the command to have run", res.Stdout)
	}
}

// An empty work dir means "inherit", which every caller that does not care
// about cwd relies on.
func TestLocalExecutor_EmptyWorkDirStillInherits(t *testing.T) {
	res := (&LocalExecutor{}).Run(context.Background(), Request{
		Name: "echo", Command: "echo", Args: []string{"hi"},
	})
	if res.Error != "" {
		t.Fatalf("an empty work dir must keep inheriting: %s", res.Error)
	}
}
