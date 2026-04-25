package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readAllEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open events file: %v", err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// Skip malformed lines so tests that pre-seed garbage to
			// verify recovery don't fail on the same garbage at readback.
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestJSONLRecorder_AssignsSeqAndTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	rec, err := NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	defer rec.Close()

	if err := rec.Emit(RunStarted("run-001", "/repo", "llm", "tee")); err != nil {
		t.Fatalf("emit 1: %v", err)
	}
	if err := rec.Emit(PlannerRoundStarted("run-001", "planner-001", 1)); err != nil {
		t.Fatalf("emit 2: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events := readAllEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Seq != 1 || events[1].Seq != 2 {
		t.Errorf("seq = %d,%d, want 1,2", events[0].Seq, events[1].Seq)
	}
	if events[0].Time.IsZero() {
		t.Errorf("seq 1 time is zero")
	}
	if events[0].Type != TypeRunStarted {
		t.Errorf("type[0] = %q, want %q", events[0].Type, TypeRunStarted)
	}
	if events[0].Target != "/repo" || events[0].Mode != "llm" || events[0].Focus != "tee" {
		t.Errorf("run_started fields not preserved: %+v", events[0])
	}
	if events[1].Type != TypePlannerRoundStarted || events[1].Round != 1 {
		t.Errorf("planner_round_started fields wrong: %+v", events[1])
	}
}

func TestJSONLRecorder_RecoversSeqOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	rec1, err := NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("rec1: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := rec1.Emit(RunStarted("r", "t", "m", "f")); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if err := rec1.Close(); err != nil {
		t.Fatalf("close rec1: %v", err)
	}

	// Reopen and ensure new events get seq=6,7,...
	rec2, err := NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("rec2: %v", err)
	}
	if err := rec2.Emit(RunCompleted("r", "done", "")); err != nil {
		t.Fatalf("emit on reopen: %v", err)
	}
	if err := rec2.Close(); err != nil {
		t.Fatalf("close rec2: %v", err)
	}

	events := readAllEvents(t, path)
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6", len(events))
	}
	if events[5].Seq != 6 {
		t.Errorf("post-reopen seq = %d, want 6", events[5].Seq)
	}
	if events[5].Type != TypeRunCompleted {
		t.Errorf("type = %q, want %q", events[5].Type, TypeRunCompleted)
	}
}

func TestJSONLRecorder_SkipsMalformedLinesOnRecover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// Pre-seed with a mix of valid and garbage lines. seq should
	// recover to 7 (max valid seq), garbage skipped.
	body := `{"seq":3,"type":"run_started","run_id":"a"}` + "\n" +
		"this is not json\n" +
		`{"seq":7,"type":"planner_round_started","run_id":"a"}` + "\n" +
		"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec, err := NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	if err := rec.Emit(RunCompleted("a", "done", "")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events := readAllEvents(t, path)
	// scanner skips the garbage line during read, so we get 3 valid events
	if len(events) != 3 {
		t.Fatalf("valid events = %d, want 3", len(events))
	}
	if events[2].Seq != 8 {
		t.Errorf("post-garbage seq = %d, want 8", events[2].Seq)
	}
}

func TestNopRecorder(t *testing.T) {
	var r Recorder = Nop{}
	if err := r.Emit(RunStarted("r", "t", "m", "f")); err != nil {
		t.Errorf("nop emit error: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("nop close error: %v", err)
	}
}

func TestBlobStore_Write(t *testing.T) {
	dir := t.TempDir()
	bs, err := NewBlobStore(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	body := []byte("hello, blob")
	ref, err := bs.Write(body)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.HasPrefix(ref, "sha256:") || len(ref) != len("sha256:")+64 {
		t.Errorf("ref looks wrong: %q", ref)
	}

	// Idempotent — second write returns same ref, no new file.
	ref2, err := bs.Write(body)
	if err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if ref != ref2 {
		t.Errorf("ref mismatch on second write: %q vs %q", ref, ref2)
	}

	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Errorf("blob dir has %d files, want 1", len(files))
	}

	// Verify on-disk content.
	hex := strings.TrimPrefix(ref, "sha256:")
	got, err := os.ReadFile(filepath.Join(dir, hex+".txt"))
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("blob content = %q, want %q", got, body)
	}
}

func TestBlobStore_WriteString(t *testing.T) {
	bs, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ref, err := bs.WriteString("payload")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.HasPrefix(ref, "sha256:") {
		t.Errorf("ref = %q", ref)
	}
}
