package codeql

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

func TestRecordsDatabaseCreate(t *testing.T) {
	bin, _ := fakeCodeQL(t, "extraction complete", "", "", 0)
	h := eventstest.New(t)

	e := NewWithBin(bin)
	e.Exec = &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	if err := e.CreateDatabase(context.Background(), CreateDBOptions{
		Language:   "cpp",
		SourceRoot: "/src/tree",
		DBPath:     "/out/db",
		Overwrite:  true,
		BuildMode:  "none",
	}); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}

	started, completed := h.ToolEvents(h.Events(), 0)
	if started.ToolName != "codeql-database-create" {
		t.Errorf("tool_name = %q, want codeql-database-create", started.ToolName)
	}
	wantArgs := strings.Join([]string{
		"database", "create", "/out/db",
		"--language=cpp", "--source-root=/src/tree",
		"--overwrite", "--build-mode=none",
	}, "\n")
	if got := h.Blob(started.ToolArgsBlob); got != wantArgs {
		t.Errorf("args blob =\n%q\nwant\n%q", got, wantArgs)
	}
	if !completed.ToolOK {
		t.Error("tool_ok = false, want true")
	}
	if got := h.Blob(completed.ToolOutputBlob); strings.TrimSpace(got) != "extraction complete" {
		t.Errorf("stdout blob = %q", got)
	}
}

func TestRecordsAnalyze(t *testing.T) {
	bin, _ := fakeCodeQL(t, "", "note: 1 query run", emptySARIF, 0)
	h := eventstest.New(t)

	e := NewWithBin(bin)
	e.Exec = &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	if _, err := e.Analyze(context.Background(), AnalyzeOptions{
		DBPath:  "/out/db",
		Queries: []string{"q.ql"},
	}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	started, completed := h.ToolEvents(h.Events(), 0)
	if started.ToolName != "codeql-database-analyze" {
		t.Errorf("tool_name = %q, want codeql-database-analyze", started.ToolName)
	}
	args := strings.Split(h.Blob(started.ToolArgsBlob), "\n")
	if len(args) != 7 || args[0] != "database" || args[1] != "analyze" || args[6] != "q.ql" {
		t.Errorf("args blob lines = %q", args)
	}
	if !strings.HasPrefix(args[4], "--output=") {
		t.Errorf("args blob must record the SARIF output path, got %q", args[4])
	}
	if got := h.Blob(completed.ToolStderrBlob); strings.TrimSpace(got) != "note: 1 query run" {
		t.Errorf("stderr blob = %q", got)
	}
}

// A failing codeql run must record its output and its error, and the
// caller must still get the same error string it always got.
func TestRecordsFailingRun(t *testing.T) {
	bin, _ := fakeCodeQL(t, "progress", "fatal: extractor exploded", "", 32)
	h := eventstest.New(t)

	e := NewWithBin(bin)
	e.Exec = &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	err := e.CreateDatabase(context.Background(), CreateDBOptions{
		Language: "cpp", SourceRoot: "/s", DBPath: "/d",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "codeql database create failed: exit status 32\n") {
		t.Errorf("err = %q", err)
	}

	_, completed := h.ToolEvents(h.Events(), 0)
	if completed.ToolOK {
		t.Error("tool_ok = true on a failing run")
	}
	if completed.ToolExitCode != 32 {
		t.Errorf("tool_exit_code = %d, want 32", completed.ToolExitCode)
	}
	if got := h.Blob(completed.ToolStderrBlob); strings.TrimSpace(got) != "fatal: extractor exploded" {
		t.Errorf("stderr blob = %q", got)
	}
	if got := h.Blob(completed.ToolOutputBlob); strings.TrimSpace(got) != "progress" {
		t.Errorf("stdout blob = %q", got)
	}
}

// No executor supplied: still works, records nothing.
func TestNoExecutorStillWorksAndRecordsNothing(t *testing.T) {
	bin, _ := fakeCodeQL(t, "", "", emptySARIF, 0)
	h := eventstest.New(t)

	if _, err := NewWithBin(bin).Analyze(context.Background(), AnalyzeOptions{
		DBPath: "/d", Queries: []string{"q.ql"},
	}); err != nil {
		t.Fatalf("Analyze without executor: %v", err)
	}
	for _, ev := range h.Events() {
		if ev.Type == events.TypeToolCallStarted || ev.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", ev.Type)
		}
	}
}

// CodeQL's console output can be very large. The executor caps it and
// flags the cut; the error message must say so too, because a `tail` of a
// truncated buffer is no longer the tail of what the process said.
func TestOversizeOutputIsFlaggedInEventAndError(t *testing.T) {
	restore := codeqlMaxOutputBytes
	codeqlMaxOutputBytes = 4096
	t.Cleanup(func() { codeqlMaxOutputBytes = restore })

	dir := t.TempDir()
	bin := dir + "/codeql"
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nhead -c 1048576 /dev/zero | tr '\\0' 'x'\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := eventstest.New(t)

	e := NewWithBin(bin)
	e.Exec = &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	err := e.CreateDatabase(context.Background(), CreateDBOptions{
		Language: "cpp", SourceRoot: "/s", DBPath: "/d",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("err = %q, want it to disclose truncation", truncateForMsg(err.Error()))
	}

	_, completed := h.ToolEvents(h.Events(), 0)
	if !completed.Truncated {
		t.Error("truncated = false on the event; a shortened record must say so")
	}
}

func truncateForMsg(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
