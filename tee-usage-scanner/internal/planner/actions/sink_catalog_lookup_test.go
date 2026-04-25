package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

const testCatalogJSON = `{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "remote attestation chain",
      "categories": [
        {
          "id": "verify",
          "description": "verify entry points",
          "match": { "kind": "symbol", "symbols": ["*::verify_quote"] },
          "severity_hint": "high"
        }
      ]
    },
    {
      "id": "key_lifecycle",
      "description": "key generation and use",
      "categories": [
        {
          "id": "generation",
          "description": "key generation",
          "match": { "kind": "symbol", "symbols": ["KeyPair::generate"] },
          "severity_hint": "high"
        }
      ]
    }
  ]
}`

func writeTestCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(path, []byte(testCatalogJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func lookupArgs(t *testing.T, scope string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"scope": scope})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSinkCatalogLookup_AllScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "*"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "attestation") {
		t.Fatalf("expected attestation, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("expected key_lifecycle, got: %s", result.Output)
	}
	// Categories must NOT be in the all-scope output.
	if strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("'*' scope leaked category details: %s", result.Output)
	}
}

func TestSinkCatalogLookup_GroupScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "verify") {
		t.Fatalf("expected verify category, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "*::verify_quote") {
		t.Fatalf("expected match patterns in group scope, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("group scope leaked other groups: %s", result.Output)
	}
}

func TestSinkCatalogLookup_CategoryScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation.verify"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "*::verify_quote") {
		t.Fatalf("expected verify pattern, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("category scope leaked other groups: %s", result.Output)
	}
}

func TestSinkCatalogLookup_UnknownGroup(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for unknown group")
	}
}

func TestSinkCatalogLookup_UnknownCategory(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation.nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for unknown category")
	}
}

func TestSinkCatalogLookup_EmptyScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := &actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, ""),
	})
	if result.OK {
		t.Fatal("expected failure for empty scope")
	}
}

func TestSinkCatalogLookup_MissingCatalog(t *testing.T) {
	h := &actions.SinkCatalogLookupHandler{CatalogPath: "/nonexistent/path.json"}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "*"),
	})
	if result.OK {
		t.Fatal("expected failure when catalog file missing")
	}
}
