package runvalidate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestValidate_AcceptsCompleteBundle(t *testing.T) {
	dir := validBundle(t)

	report := Validate(dir)
	if !report.Valid {
		t.Fatalf("Validate() rejected valid bundle: %+v", report.Issues)
	}
}

func TestValidate_RejectsEventSequenceGap(t *testing.T) {
	dir := validBundle(t)
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeEvents(t, eventsPath,
		events.Event{Seq: 1, Type: events.TypeRunStarted, RunID: "run-1"},
		events.Event{Seq: 3, Type: events.TypeRunCompleted, RunID: "run-1", Reason: "completed"},
	)

	assertIssue(t, Validate(dir), "event_sequence")
}

func TestValidate_RejectsMissingOrFailedTerminalEvent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []events.Event
		code   string
	}{
		{
			name:   "missing",
			events: []events.Event{{Seq: 1, Type: events.TypeRunStarted, RunID: "run-1"}},
			code:   "terminal_event",
		},
		{
			name: "failed",
			events: []events.Event{
				{Seq: 1, Type: events.TypeRunStarted, RunID: "run-1"},
				{Seq: 2, Type: events.TypeRunCompleted, RunID: "run-1", Reason: "error"},
			},
			code: "terminal_status",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := validBundle(t)
			writeEvents(t, filepath.Join(dir, "events.jsonl"), tc.events...)
			assertIssue(t, Validate(dir), tc.code)
		})
	}
}

func TestValidate_RejectsBrokenBlobReferences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, dir string)
		code   string
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, "blobs", hashOf("prompt")+".txt")); err != nil {
					t.Fatal(err)
				}
			},
			code: "blob_missing",
		},
		{
			name: "hash mismatch",
			mutate: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "blobs", hashOf("prompt")+".txt"), []byte("changed"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			code: "blob_hash",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := validBundle(t)
			tc.mutate(t, dir)
			assertIssue(t, Validate(dir), tc.code)
		})
	}
}

func TestValidate_RejectsRunIDMismatch(t *testing.T) {
	dir := validBundle(t)
	writeEvents(t, filepath.Join(dir, "events.jsonl"),
		events.Event{Seq: 1, Type: events.TypeRunStarted, RunID: "another-run"},
		events.Event{Seq: 2, Type: events.TypeRunCompleted, RunID: "run-1", Reason: "completed"},
	)

	assertIssue(t, Validate(dir), "event_run_id")
}

func TestValidate_RejectsInvalidFindingsContract(t *testing.T) {
	dir := validBundle(t)
	bad := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "run-1",
		Findings: []artifacts.FindingItem{{
			FindingID: "f-1", SliceID: "s-1", Status: "maybe",
			Severity: "high", Confidence: "medium", Summary: "summary",
		}},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), bad); err != nil {
		t.Fatal(err)
	}

	assertIssue(t, Validate(dir), "findings_contract")
}

func TestValidate_RejectsCompletedStageWithoutRequiredArtifact(t *testing.T) {
	dir := validBundle(t)
	writeEvents(t, filepath.Join(dir, "events.jsonl"),
		events.Event{Seq: 1, Type: events.TypeRunStarted, RunID: "run-1"},
		events.Event{Seq: 2, Type: events.TypeStageStarted, RunID: "run-1", Stage: "architecture"},
		events.Event{Seq: 3, Type: events.TypeStageCompleted, RunID: "run-1", Stage: "architecture", Reason: "completed"},
		events.Event{Seq: 4, Type: events.TypeRunCompleted, RunID: "run-1", Reason: "completed"},
	)

	assertIssue(t, Validate(dir), "stage_artifact_missing")
}

func validBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1"}
	if err := runfs.WriteJSON(runfs.ManifestPath(dir), manifest); err != nil {
		t.Fatal(err)
	}
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "run-1",
		Findings:      make([]artifacts.FindingItem, 0),
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), findings); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", hashOf("prompt")+".txt"), []byte("prompt"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeEvents(t, filepath.Join(dir, "events.jsonl"),
		events.Event{Seq: 1, Type: events.TypeRunStarted, RunID: "run-1"},
		events.Event{Seq: 2, Type: events.TypeLLMCallCompleted, RunID: "run-1", PromptBlob: "sha256:" + hashOf("prompt")},
		events.Event{Seq: 3, Type: events.TypeRunCompleted, RunID: "run-1", Reason: "completed"},
	)
	return dir
}

func writeEvents(t *testing.T, path string, all ...events.Event) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, event := range all {
		if event.Time.IsZero() {
			event.Time = time.Unix(event.Seq, 0).UTC()
		}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func hashOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func assertIssue(t *testing.T, report Report, code string) {
	t.Helper()
	for _, issue := range report.Issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("Validate() issues = %+v, want code %q", report.Issues, code)
}
