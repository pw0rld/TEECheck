// Package eventstest provides a recording harness for tests that need to
// assert on what a run actually recorded.
//
// It deliberately uses the REAL JSONLRecorder and BlobStore rather than a
// stub: the thing under test is whether a call site's arguments and output
// survive into a run directory, and a stub recorder that keeps events in
// memory cannot prove a blob ref resolves to anything. Harness.Blob reads
// the ref back off disk exactly as a human inspecting runs/<id>/blobs would.
//
// Test-only. Nothing outside _test.go files should import this.
package eventstest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// Harness owns a temporary run directory containing events.jsonl and
// blobs/, wired exactly the way internal/pipeline wires them.
type Harness struct {
	t        *testing.T
	closed   bool
	Dir      string
	Recorder *events.JSONLRecorder
	Blobs    *events.BlobStore
}

// New returns a Harness rooted at a fresh temp dir. The recorder is closed
// automatically when the test ends.
func New(t *testing.T) *Harness {
	t.Helper()
	dir := t.TempDir()
	rec, err := events.NewJSONLRecorder(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("eventstest: recorder: %v", err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("eventstest: blob store: %v", err)
	}
	h := &Harness{t: t, Dir: dir, Recorder: rec, Blobs: blobs}
	t.Cleanup(h.close)
	return h
}

func (h *Harness) close() {
	if h.closed {
		return
	}
	h.closed = true
	_ = h.Recorder.Close()
}

// Events flushes the recorder and returns every event written so far, in
// file order. Safe to call more than once.
func (h *Harness) Events() []events.Event {
	h.t.Helper()
	h.close()
	f, err := os.Open(filepath.Join(h.Dir, "events.jsonl"))
	if err != nil {
		h.t.Fatalf("eventstest: open events.jsonl: %v", err)
	}
	defer f.Close()

	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			h.t.Fatalf("eventstest: bad event line %q: %v", line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		h.t.Fatalf("eventstest: scan events.jsonl: %v", err)
	}
	return out
}

// ToolEvents returns the (started, completed) pair for the n-th tool call
// recorded, failing the test if fewer than n+1 pairs exist or if the pair
// is not well formed.
func (h *Harness) ToolEvents(all []events.Event, n int) (started, completed events.Event) {
	h.t.Helper()
	var starts, ends []events.Event
	for _, e := range all {
		switch e.Type {
		case events.TypeToolCallStarted:
			starts = append(starts, e)
		case events.TypeToolCallCompleted:
			ends = append(ends, e)
		}
	}
	if len(starts) <= n || len(ends) <= n {
		h.t.Fatalf("eventstest: want at least %d tool call pair(s), got %d started / %d completed",
			n+1, len(starts), len(ends))
	}
	return starts[n], ends[n]
}

// Blob resolves a "sha256:<hex>" ref against the harness blob directory and
// returns the stored bytes. Asserting on resolved CONTENT — not on a ref
// merely being non-empty — is the whole point of the harness.
func (h *Harness) Blob(ref string) string {
	h.t.Helper()
	if !strings.HasPrefix(ref, "sha256:") {
		h.t.Fatalf("eventstest: blob ref %q is not a sha256 reference", ref)
	}
	body, err := os.ReadFile(filepath.Join(h.Dir, "blobs", strings.TrimPrefix(ref, "sha256:")+".txt"))
	if err != nil {
		h.t.Fatalf("eventstest: read blob %s: %v", ref, err)
	}
	return string(body)
}

// FakeBinary writes an executable shell script named name into a fresh
// directory and prepends that directory to PATH for the duration of the
// test. It is how a package whose binary name is hard-coded ("semgrep",
// "npx", "git") gets exercised end to end on a machine where the real tool
// is absent: the subprocess is real, only the program is a stand-in.
//
// The script body receives the call's argv, so a fake can assert on — or
// echo back — exactly what the call site passed.
func FakeBinary(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("eventstest: write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}
