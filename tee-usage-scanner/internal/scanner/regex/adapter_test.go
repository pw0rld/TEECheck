package regex_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/regex"
)

func TestRegexAdapterRust(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "verify.rs"), []byte("pub fn verify_quote(report: &Report) -> Result<(), Error> {\n    verify_qe_identity_policy(report)?;\n    Ok(())\n}\n\nfn verify_qe_identity_policy(report: &Report) -> Result<(), Error> {\n    Ok(())\n}\n\npub struct AttestationReport {\n    pub quote: Vec<u8>,\n}\n"), 0o644)

	a := regex.New()
	if a.Name() != "regex" {
		t.Fatalf("expected name regex, got %s", a.Name())
	}
	if !a.Available() {
		t.Fatal("expected regex to be available")
	}

	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fileNodes := 0
	funcNodes := 0
	structNodes := 0
	for _, n := range result.Nodes {
		switch n.Kind {
		case "file":
			fileNodes++
		case "function":
			funcNodes++
		case "struct":
			structNodes++
		}
	}
	if fileNodes != 1 {
		t.Fatalf("expected 1 file node, got %d", fileNodes)
	}
	if funcNodes != 2 {
		t.Fatalf("expected 2 function nodes, got %d", funcNodes)
	}
	if structNodes != 1 {
		t.Fatalf("expected 1 struct node, got %d", structNodes)
	}

	definesCount := 0
	for _, e := range result.Edges {
		if e.Kind == "defines" {
			definesCount++
		}
	}
	if definesCount < 3 {
		t.Fatalf("expected at least 3 defines edges, got %d", definesCount)
	}
}

func TestRegexAdapterGo(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc HandleRequest(w http.ResponseWriter, r *http.Request) {\n    processData(r.Body)\n}\n\nfunc processData(data io.Reader) error {\n    return nil\n}\n\ntype Server struct {\n    addr string\n}\n"), 0o644)

	a := regex.New()
	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	funcNodes := 0
	structNodes := 0
	for _, n := range result.Nodes {
		switch n.Kind {
		case "function":
			funcNodes++
		case "struct":
			structNodes++
		}
	}
	if funcNodes != 2 {
		t.Fatalf("expected 2 function nodes, got %d", funcNodes)
	}
	if structNodes != 1 {
		t.Fatalf("expected 1 struct node, got %d", structNodes)
	}
}

func TestRegexAdapterSkipsDirs(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "dep")
	os.MkdirAll(nm, 0o755)
	os.WriteFile(filepath.Join(nm, "index.ts"), []byte("export function ignored() {}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "app.ts"), []byte("export function real() {}\n"), 0o644)

	a := regex.New()
	result, err := a.ExtractGraph(context.Background(), scanner.GraphRequest{RepoRoot: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, n := range result.Nodes {
		if n.Name == "ignored" {
			t.Fatal("should have skipped node_modules")
		}
	}
}

var _ scanner.GraphAdapter = (*regex.Adapter)(nil)
