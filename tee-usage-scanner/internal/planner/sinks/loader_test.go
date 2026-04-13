package sinks_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

const validCatalogJSON = `{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "remote attestation chain",
      "categories": [
        {
          "id": "attestation_verify",
          "description": "verify entry points",
          "match": { "kind": "symbol", "symbols": ["*::verify_quote*"] },
          "severity_hint": "high"
        }
      ]
    }
  ]
}`

func writeCatalog(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_HappyPath(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)

	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cat.SchemaVersion != sinks.SchemaVersion {
		t.Fatalf("got schema %q, want %q", cat.SchemaVersion, sinks.SchemaVersion)
	}
	if cat.Language != "rust" {
		t.Fatalf("got language %q, want rust", cat.Language)
	}
	if len(cat.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(cat.Groups))
	}
	if cat.Groups[0].ID != "attestation" {
		t.Fatalf("got group id %q, want attestation", cat.Groups[0].ID)
	}
	if len(cat.Groups[0].Categories) != 1 {
		t.Fatalf("got %d categories, want 1", len(cat.Groups[0].Categories))
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := sinks.Load("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_RejectsWrongSchemaVersion(t *testing.T) {
	bad := strings.Replace(validCatalogJSON, "v2", "v99", 1)
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for wrong schema version")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema_version error, got %v", err)
	}
}

func TestLoad_RejectsEmptyGroups(t *testing.T) {
	bad := `{"schema_version": "teecheck.sink_catalog.v2", "language": "rust", "groups": []}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for empty groups")
	}
	if !strings.Contains(err.Error(), "groups") {
		t.Fatalf("expected groups error, got %v", err)
	}
}

func TestLoad_RejectsCategoryMissingMatchKind(t *testing.T) {
	bad := `{
		"schema_version": "teecheck.sink_catalog.v2",
		"language": "rust",
		"groups": [{
			"id": "g1", "description": "x",
			"categories": [{
				"id": "c1", "description": "x",
				"match": {},
				"severity_hint": "high"
			}]
		}]
	}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for missing match.kind")
	}
}

func TestLoad_RejectsSymbolKindWithPatterns(t *testing.T) {
	bad := `{
		"schema_version": "teecheck.sink_catalog.v2",
		"language": "rust",
		"groups": [{
			"id": "g1", "description": "x",
			"categories": [{
				"id": "c1", "description": "x",
				"match": { "kind": "symbol", "patterns": ["foo"] },
				"severity_hint": "high"
			}]
		}]
	}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for symbol kind with patterns")
	}
}

func TestLoad_RustJSONFromKnowledge(t *testing.T) {
	// Load the real on-disk rust.json from knowledge/sinks/.
	// Test runs from internal/planner/sinks; go up three levels.
	path := filepath.Join("..", "..", "..", "knowledge", "sinks", "rust.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("knowledge/sinks/rust.json not found at %s: %v", path, err)
	}

	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatalf("real catalog failed to load: %v", err)
	}
	if len(cat.Groups) != 3 {
		t.Fatalf("expected 3 groups in real catalog, got %d", len(cat.Groups))
	}

	totalCategories := 0
	for _, g := range cat.Groups {
		totalCategories += len(g.Categories)
	}
	if totalCategories != 13 {
		t.Fatalf("expected 13 total categories in real catalog, got %d", totalCategories)
	}
}

func TestLookupGroup(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	g, err := cat.LookupGroup("attestation")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if g.ID != "attestation" {
		t.Fatalf("got %q", g.ID)
	}

	_, err = cat.LookupGroup("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestLookupCategory(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	c, err := cat.LookupCategory("attestation", "attestation_verify")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c.ID != "attestation_verify" {
		t.Fatalf("got %q", c.ID)
	}

	_, err = cat.LookupCategory("attestation", "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestGroupHeaders(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	headers := cat.GroupHeaders()
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	if headers[0].ID != "attestation" {
		t.Fatalf("got %q", headers[0].ID)
	}
	if headers[0].Description == "" {
		t.Fatal("expected non-empty description")
	}
	if len(headers[0].Categories) != 0 {
		t.Fatalf("GroupHeaders must strip categories, got %d", len(headers[0].Categories))
	}
}
