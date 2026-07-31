package trustirfacts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPersist_WritesSchemaValidFact(t *testing.T) {
	runDir := t.TempDir()
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "trustir-cpp-test-fact",
		Tool:          toolName,
		Operation:     string(OperationRollbackVersionPropagation),
		RepoCommit:    "abc123",
		Status:        StatusSuccess,
	}

	path, err := Persist(runDir, fact)
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	wantPath := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if path != wantPath {
		t.Errorf("path = %q, want %q", path, wantPath)
	}

	var roundTripped artifacts.ToolFact
	if err := runfs.ReadJSON(path, &roundTripped); err != nil {
		t.Fatalf("read back persisted fact: %v", err)
	}
	if roundTripped.FactID != fact.FactID || roundTripped.Status != fact.Status {
		t.Errorf("round-tripped fact = %+v, want %+v", roundTripped, fact)
	}
}

func TestPersist_RejectsInvalidStatus(t *testing.T) {
	runDir := t.TempDir()
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "trustir-cpp-bad-fact",
		Tool:          toolName,
		Operation:     string(OperationRollbackVersionPropagation),
		RepoCommit:    "abc123",
		Status:        "not-a-real-status",
	}
	if _, err := Persist(runDir, fact); err == nil {
		t.Fatal("expected schema validation to reject an unrecognized status")
	}
}

// TestPersist_IsIdempotent proves ToolFact's documented immutability: a
// second Persist call for the same FactID does not rewrite the file, even
// if (contrived here) the in-memory fact has since changed shape.
func TestPersist_IsIdempotent(t *testing.T) {
	runDir := t.TempDir()
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "trustir-cpp-idempotent",
		Tool:          toolName,
		Operation:     string(OperationRollbackVersionPropagation),
		RepoCommit:    "abc123",
		Status:        StatusSuccess,
	}
	path, err := Persist(runDir, fact)
	if err != nil {
		t.Fatalf("first Persist: %v", err)
	}
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	changed := fact
	changed.Status = StatusError
	changed.Error = "this must never reach disk"
	if _, err := Persist(runDir, changed); err != nil {
		t.Fatalf("second Persist: %v", err)
	}
	secondBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Error("Persist must not overwrite an already-persisted fact")
	}
}

func TestPersist_CreatesToolFactsDir(t *testing.T) {
	runDir := t.TempDir()
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "trustir-cpp-dir-test",
		Tool:          toolName,
		Operation:     string(OperationRollbackVersionPropagation),
		RepoCommit:    "abc123",
		Status:        StatusUnsupported,
		Error:         "no fact table",
	}
	if _, err := Persist(runDir, fact); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runfs.TrustIRToolFactsDir(runDir))); err != nil {
		t.Errorf("expected TrustIRToolFactsDir to exist: %v", err)
	}
}

// Persist must return an absolute path even when RunDir is relative.
//
// internal/investigations' validateToolFactRefs resolves a relative ref
// against the REPO root, not the run dir — its doc comment says refs "are
// expected to be the absolute path RunAndPersist / Persist returned". When
// the pipeline is invoked with the default --output-dir of "runs", RunDir is
// relative, so the ref came back relative, was joined onto the scanned
// repository's path, did not exist there, and was silently dropped. The
// 2026-07-31 vulnerable-side run collected the correct ToolFact —
// signed_hdr.c:262 — and delivered it to nobody.
func TestPersist_ReturnsAbsolutePathForRelativeRunDir(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "trustir-cpp-test-abs",
		Tool:          "trustir-cpp",
		Operation:     string(OperationRollbackVersionPropagation),
		RepoCommit:    "deadbeef",
		Status:        StatusSuccess,
	}
	path, err := Persist("runs/relative-run", fact)
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("Persist returned %q; a relative ref is resolved against the repo root by "+
			"investigations.validateToolFactRefs and silently dropped", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("returned path must resolve: %v", err)
	}
}
