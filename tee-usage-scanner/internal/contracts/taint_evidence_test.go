package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func taintEvidenceFixture(t *testing.T) (BindingContext, artifacts.ToolFact, string) {
	t.Helper()
	ctx := fixture(t, "int load(void) { return 1; }\n", "revision")
	ctx.RunDir = t.TempDir()
	ctx.Scope = runfs.BuildScope("fixture", "revision", ctx.RepoRoot)
	scope := ctx.Scope
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1, RequestID: "trace-request", FactID: "taint-" + strings.Repeat("b", 64),
		Tool: "codeql-cpp-taint", Operation: "cpp.taint.trace", RepoCommit: scope.Commit, Scope: &scope, Status: "success",
		ArgumentsSHA256: strings.Repeat("b", 64), Result: json.RawMessage(`{"total_paths":0,"barriers_applied":[]}`),
		CoverageGaps: []string{"No paths does not prove safety."},
	}
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	path := filepath.Join(runfs.TrustIRToolFactsDir(ctx.RunDir), "taint-evidence.json")
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	return ctx, fact, path
}

func TestTaintEvidenceLoadAndResolveBindExactFile(t *testing.T) {
	ctx, fact, path := taintEvidenceFixture(t)
	loaded, err := LoadToolFact(path, ctx)
	if err != nil || loaded.FactID != fact.FactID || loaded.Scope == nil {
		t.Fatalf("valid immutable evidence was not loaded: fact=%+v error=%v", loaded, err)
	}
	ref, err := ResolveEvidence(artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(body)
	if ref.ContentSHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("contract evidence did not bind the exact persisted bytes")
	}
	// Updating both payload and its self-check still changes the persisted
	// file. A frozen contract reference must continue to reject that change.
	fact.Result = json.RawMessage(`{"total_paths":1,"barriers_applied":[]}`)
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveEvidence(ref, ctx); err == nil {
		t.Fatal("replacing an immutable ToolFact bypassed the frozen reference hash")
	}
}

func TestTaintEvidenceRejectsTamperAndScopeMismatch(t *testing.T) {
	for _, mode := range []string{"content", "repository", "commit", "scope hash"} {
		t.Run(mode, func(t *testing.T) {
			ctx, fact, path := taintEvidenceFixture(t)
			switch mode {
			case "content":
				fact.Result = json.RawMessage(`{"total_paths":100}`)
			case "repository":
				fact.Scope.RepoURL = "different-project"
			case "commit":
				fact.Scope.Commit = "different-commit"
			case "scope hash":
				fact.Scope.Hash = "different-scope-hash"
			}
			if mode != "content" {
				fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			}
			if err := runfs.WriteJSON(path, fact); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadToolFact(path, ctx); err == nil {
				t.Fatal("invalid evidence was accepted by the review loader")
			}
			if _, err := ResolveEvidence(artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path}, ctx); err == nil {
				t.Fatal("invalid evidence was accepted by contract binding")
			}
		})
	}
}
