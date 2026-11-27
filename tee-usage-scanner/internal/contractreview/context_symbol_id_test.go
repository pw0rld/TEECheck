package contractreview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Regression 5: When two different files define static functions with the same
// name, surroundingSourceContext MUST resolve the contract subject by exact
// (path, symbol, line range) -> SymbolID so only the target subject's callers,
// callees, and StructFieldBridge partners are included.
func TestSurroundingSourceContext_IsolatesSameNameStaticFunctions(t *testing.T) {
	root := t.TempDir()
	run := t.TempDir()

	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("core/alpha.c", "/* alpha header */\n\nstatic int validate_param(int x) {\n    return x > 0;\n}\n")
	write("core/beta.c", "/* beta header */\n\nstatic int validate_param(int x) {\n    return x < 100;\n}\n")
	write("core/alpha_caller.c", "int alpha_entry(int x) {\n    return validate_param(x);\n}\n")
	write("core/beta_caller.c", "int beta_entry(int x) {\n    return validate_param(x);\n}\n")
	write("core/alpha_consumer.c", "void alpha_consume(void) {\n    /* ALPHA_CONSUMER_MARKER */\n}\n")
	write("core/beta_consumer.c", "void beta_consume(void) {\n    /* BETA_CONSUMER_MARKER */\n}\n")

	symAlpha := artifacts.MakeSymbolID("cpp", "core/alpha.c", 3, "validate_param", "(int)")
	symBeta := artifacts.MakeSymbolID("cpp", "core/beta.c", 3, "validate_param", "(int)")
	symAlphaCaller := artifacts.MakeSymbolID("cpp", "core/alpha_caller.c", 1, "alpha_entry", "(int)")
	symBetaCaller := artifacts.MakeSymbolID("cpp", "core/beta_caller.c", 1, "beta_entry", "(int)")
	symAlphaConsumer := artifacts.MakeSymbolID("cpp", "core/alpha_consumer.c", 1, "alpha_consume", "()")
	symBetaConsumer := artifacts.MakeSymbolID("cpp", "core/beta_consumer.c", 1, "beta_consume", "()")

	scope := runfs.BuildScope("fixture", "rev", root)
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{RunID: "static-iso", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	facts := artifacts.RepoFacts{
		SchemaVersion: "teecheck.repo_facts.v1",
		RunID:         "static-iso",
		Scope:         scope,
		Symbols: []artifacts.Symbol{
			{SymbolID: symAlpha, Name: "validate_param", File: "core/alpha.c", StartLine: 3},
			{SymbolID: symBeta, Name: "validate_param", File: "core/beta.c", StartLine: 3},
			{SymbolID: symAlphaCaller, Name: "alpha_entry", File: "core/alpha_caller.c", StartLine: 1},
			{SymbolID: symBetaCaller, Name: "beta_entry", File: "core/beta_caller.c", StartLine: 1},
			{SymbolID: symAlphaConsumer, Name: "alpha_consume", File: "core/alpha_consumer.c", StartLine: 1},
			{SymbolID: symBetaConsumer, Name: "beta_consume", File: "core/beta_consumer.c", StartLine: 1},
		},
		CallEdges: []artifacts.CallEdge{
			{CallerID: symAlphaCaller, CalleeID: symAlpha},
			{CallerID: symBetaCaller, CalleeID: symBeta},
		},
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), facts); err != nil {
		t.Fatal(err)
	}

	topo := artifacts.BoundaryTopology{
		SchemaVersion: artifacts.SchemaVersionBoundaryTopologyV1,
		RunID:         "static-iso",
		Scope:         scope,
		StructFieldBridges: []artifacts.StructFieldBridge{
			{
				Field:             "struct alpha_ctx::len",
				CrossModule:       true,
				DirectWriters:     []artifacts.SymbolID{symAlpha},
				NonWriteAccessors: []artifacts.SymbolID{symAlphaConsumer},
			},
			{
				Field:             "struct beta_ctx::len",
				CrossModule:       true,
				DirectWriters:     []artifacts.SymbolID{symBeta},
				NonWriteAccessors: []artifacts.SymbolID{symBetaConsumer},
			},
		},
	}
	if err := runfs.WriteJSON(runfs.BoundaryTopologyPath(run), topo); err != nil {
		t.Fatal(err)
	}

	c := artifacts.CaseInvariantV2{
		InvariantID: "inv-alpha",
		Scope:       scope,
		Subjects: []artifacts.ContractSubject{
			{Path: "core/alpha.c", Symbol: "validate_param", StartLine: 3, EndLine: 5},
		},
	}
	ctxText := surroundingSourceContext(contracts.BindingContext{RepoRoot: root, RunDir: run, Scope: scope}, c)

	if !strings.Contains(ctxText, "alpha_entry") {
		t.Fatalf("expected alpha_entry caller in context, got:\n%s", ctxText)
	}
	if !strings.Contains(ctxText, "ALPHA_CONSUMER_MARKER") {
		t.Fatalf("expected alpha_consume struct-field partner in context, got:\n%s", ctxText)
	}
	if strings.Contains(ctxText, "beta_entry") || strings.Contains(ctxText, "BETA_CONSUMER_MARKER") || strings.Contains(ctxText, "core/beta.c") {
		t.Fatalf("cross-contaminated context with same-name static function from core/beta.c:\n%s", ctxText)
	}
}

func TestResolveContractSubjectSymbolIDsDoesNotGuessOverloads(t *testing.T) {
	first := artifacts.MakeSymbolID("cpp", "a.cpp", 3, "check", "(int)")
	second := artifacts.MakeSymbolID("cpp", "a.cpp", 20, "check", "(long)")
	symbols := []artifacts.Symbol{
		{SymbolID: first, Name: "check", File: "a.cpp", StartLine: 3},
		{SymbolID: second, Name: "check", File: "a.cpp", StartLine: 20},
	}
	partial := artifacts.ContractSubject{Path: "./a.cpp", Symbol: "check", StartLine: 25, EndLine: 26}
	if got := resolveContractSubjectSymbolIDs([]artifacts.ContractSubject{partial}, symbols); len(got) != 0 {
		t.Fatalf("partial source window guessed a preceding overload: %v", got)
	}
	partial.SymbolID = second
	if got := resolveContractSubjectSymbolIDs([]artifacts.ContractSubject{partial}, symbols); len(got) != 1 || !got[second] {
		t.Fatalf("exact source-bound identity was not preserved: %v", got)
	}
	partial.SymbolID = "absent"
	if got := resolveContractSubjectSymbolIDs([]artifacts.ContractSubject{partial}, symbols); len(got) != 0 {
		t.Fatalf("unknown source-bound identity fell back to another definition: %v", got)
	}
}

func TestContextSourcePathRejectsEscapesAndSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.c"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../secret.c", filepath.Join(outside, "secret.c"), "linked/secret.c", "bad\x00path"} {
		if _, err := contextSourcePath(root, path); err == nil {
			t.Fatalf("untrusted index path accepted: %q", path)
		}
	}
}

func TestSurroundingSourceContextRejectsMismatchedIndexScope(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("int check(void) { return 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.c"), []byte("int foreign_caller(void) { /* FOREIGN_CONTEXT */ return check(); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "rev", root)
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{RunID: "ctx", Scope: scope}); err != nil {
		t.Fatal(err)
	}
	target := artifacts.MakeSymbolID("cpp", "a.c", 1, "check", "()")
	caller := artifacts.MakeSymbolID("cpp", "b.c", 1, "foreign_caller", "()")
	foreign := scope
	foreign.Commit = "other-revision"
	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1, RunID: "ctx", Scope: foreign,
		Symbols: []artifacts.Symbol{
			{SymbolID: target, Name: "check", File: "a.c", StartLine: 1},
			{SymbolID: caller, Name: "foreign_caller", File: "b.c", StartLine: 1},
		},
		CallEdges: []artifacts.CallEdge{{CallerID: caller, CalleeID: target}},
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), facts); err != nil {
		t.Fatal(err)
	}
	c := artifacts.CaseInvariantV2{Scope: scope, Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "check", StartLine: 1, EndLine: 1}}}
	got := surroundingSourceContext(contracts.BindingContext{RepoRoot: root, RunDir: run, Scope: scope}, c)
	if strings.Contains(got, "FOREIGN_CONTEXT") {
		t.Fatalf("foreign program index affected source context: %s", got)
	}
}

func TestSurroundingSourceContextRespectsByteBudget(t *testing.T) {
	root := t.TempDir()
	data := strings.Repeat(strings.Repeat("x", 250)+"\n", 200)
	if err := os.WriteFile(filepath.Join(root, "large.c"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	c := artifacts.CaseInvariantV2{Subjects: []artifacts.ContractSubject{{Path: "large.c", Symbol: "check", StartLine: 100, EndLine: 102}}}
	got := surroundingSourceContext(contracts.BindingContext{RepoRoot: root}, c)
	if len(got) > 32*1024 || !strings.Contains(got, "additional context omitted by byte budget") {
		t.Fatalf("unbounded or silently truncated source context: %d bytes", len(got))
	}
}
