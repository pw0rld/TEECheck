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
	if err := Validate(ProjectProfileV2, []byte(`{not json`)); err == nil {
		t.Fatal("expected an error for malformed JSON input")
	}
}
