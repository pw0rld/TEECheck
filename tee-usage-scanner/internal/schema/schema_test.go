package schema

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// canonicalDir locates the repository-root schemas/ directory relative to
// this test file's own source path (via runtime.Caller), not the process's
// working directory, so `go test ./...` from any directory finds it.
// Layout: <repo-root>/tee-usage-scanner/internal/schema/schema_test.go
func canonicalDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to resolve test file path")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "schemas")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("repository-root schemas dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestEmbeddedSchemasMatchCanonical is the drift guard the go:embed copy
// depends on: schemas/ at the repository root is the single source of
// truth, and this test fails the moment internal/schema/schemas/*.json
// stops being a byte-identical copy of it.
func TestEmbeddedSchemasMatchCanonical(t *testing.T) {
	canonical := canonicalDir(t)
	for _, name := range All {
		filename := string(name) + ".json"
		want, err := os.ReadFile(filepath.Join(canonical, filename))
		if err != nil {
			t.Fatalf("read canonical %s: %v", filename, err)
		}
		got, err := embedded.ReadFile("schemas/" + filename)
		if err != nil {
			t.Fatalf("read embedded %s: %v", filename, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("internal/schema/schemas/%s has drifted from schemas/%s; copy the canonical file over the embedded one", filename, filename)
		}
	}
}

// TestCanonicalDirHasExactlyEmbeddedSchemas guards the reverse drift: a new
// schema landing in schemas/ without a matching embedded copy and Name
// constant here.
func TestCanonicalDirHasExactlyEmbeddedSchemas(t *testing.T) {
	canonical := canonicalDir(t)
	entries, err := os.ReadDir(canonical)
	if err != nil {
		t.Fatalf("read canonical dir: %v", err)
	}
	want := make(map[string]bool, len(All))
	for _, name := range All {
		want[string(name)+".json"] = true
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		seen[entry.Name()] = true
		if !want[entry.Name()] {
			t.Errorf("schemas/%s is not embedded or listed in schema.All", entry.Name())
		}
	}
	for filename := range want {
		if !seen[filename] {
			t.Errorf("schema.All lists %s but schemas/%s does not exist", filename, filename)
		}
	}
}

func TestAllSchemasCompile(t *testing.T) {
	schemas, err := compiled()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range All {
		if _, ok := schemas[name]; !ok {
			t.Errorf("schema %s did not compile into the registry", name)
		}
	}
}

func TestValidateUnknownSchema(t *testing.T) {
	if err := Validate(Name("does-not-exist"), []byte(`{}`)); err == nil {
		t.Fatal("expected an error for an unregistered schema name")
	}
}

func TestValidateRejectsMalformedJSON(t *testing.T) {
	if err := Validate(ProjectInvariantV1, []byte(`{not json`)); err == nil {
		t.Fatal("expected an error for malformed JSON input")
	}
}

// TestSchemaVersionNotInferredFromFilename is PR-01's explicit acceptance
// check: "schema version 不依赖文件名推断" (schema_version must not be
// inferred from the file name). Validate's signature already only takes a
// caller-chosen schema.Name and the file's bytes — never a path — so this
// test proves that by writing each fixture to disk under a name that lies
// about its content, reading only the bytes back, and confirming the
// outcome tracks the JSON's own schema_version field, not the filename.
func TestSchemaVersionNotInferredFromFilename(t *testing.T) {
	valid := `{
		"schema_version": "teecheck.project_invariant.v1",
		"invariant_id": "INV-FLOW-001",
		"statement": "s",
		"related_twes": ["TWE-FLOW-001"],
		"verification_plan": ["p"],
		"status": "proposed"
	}`
	wrongVersion := `{
		"schema_version": "teecheck.project_invariant.v0",
		"invariant_id": "INV-FLOW-001",
		"statement": "s",
		"related_twes": ["TWE-FLOW-001"],
		"verification_plan": ["p"],
		"status": "proposed"
	}`
	missingVersion := `{
		"invariant_id": "INV-FLOW-001",
		"statement": "s",
		"related_twes": ["TWE-FLOW-001"],
		"verification_plan": ["p"],
		"status": "proposed"
	}`

	// A correctly-named file whose content carries the wrong (or a
	// missing) schema_version must still be rejected.
	if err := Validate(ProjectInvariantV1, readTempFile(t, "project-invariant.v1.json", wrongVersion)); err == nil {
		t.Fatal("expected a correctly-named file with the wrong schema_version to be rejected")
	}
	if err := Validate(ProjectInvariantV1, readTempFile(t, "project-invariant.v1.json", missingVersion)); err == nil {
		t.Fatal("expected a correctly-named file with a missing schema_version to be rejected")
	}

	// An oddly-named file whose content carries the correct
	// schema_version must still be accepted.
	if err := Validate(ProjectInvariantV1, readTempFile(t, "notes.txt", valid)); err != nil {
		t.Fatalf("a correct schema_version in an oddly-named file must be accepted: %v", err)
	}
	if err := Validate(ProjectInvariantV1, readTempFile(t, "definitely-not-an-invariant", valid)); err != nil {
		t.Fatalf("a correct schema_version in an extensionless, misleadingly-named file must be accepted: %v", err)
	}
}

func readTempFile(t *testing.T, name, content string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
