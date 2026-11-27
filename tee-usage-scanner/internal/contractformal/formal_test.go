package contractformal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

type stubLLM struct {
	reply string
	calls int
}

func (s *stubLLM) Generate(_ context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.calls++
	return llm.GenerateResponse{Text: s.reply}, nil
}

func formalFixture(t *testing.T) (contracts.BindingContext, artifacts.CaseInvariantV2) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("int f(int x) { return x + 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binding := contracts.BindingContext{RepoRoot: root, RunDir: run, Scope: runfs.BuildScope("fixture", "rev1", root)}
	bound, diagnostics, err := contracts.Bind(artifacts.CaseInvariantV2{
		InvariantID: "case-inv-formal", Origin: "planner",
		Subjects:         []artifacts.ContractSubject{{Path: "a.c", Symbol: "f"}},
		Preconditions:    []string{"x is a valid signed input"},
		RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "increment must not overflow"},
		SecurityEffect:   "integer bounds",
	}, binding)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("bind fixture: %v %+v", err, diagnostics)
	}
	return binding, bound
}

func translationReply(t *testing.T, source string) string {
	t.Helper()
	raw, err := json.Marshal(TranslationSpec{Applicable: true, PropertyKind: "arithmetic_overflow", CSource: source})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestExecuteHarnessFailsClosedRegardlessOfOutputClaims(t *testing.T) {
	for _, source := range []string{
		`#include <stdio.h>
int main(void) { puts("VERIFIED_UNDER_ASSUMPTIONS"); return 0; }`,
		`#include <stdio.h>
int main(void) { puts("COUNTEREXAMPLE: arbitrary model claim"); return 1; }`,
		`int main(void) { __CPROVER_assert(1, "assertion"); return 0; }`,
		`int main(void) { this_is_not_valid_c( ; }`,
	} {
		out := ExecuteHarness(context.Background(), TranslationSpec{Applicable: true, CSource: source})
		if out.Status != StatusSandboxUnavailable || out.Backend != BackendNone || out.Stdout != "" || out.Counterexample != "" {
			t.Fatalf("generated C or claimed output became an execution result: %+v", out)
		}
		if out.SourceSHA256 == "" || out.Translation == nil || out.Translation.CSource != source {
			t.Fatalf("bounded model translation was not preserved: %+v", out)
		}
	}
}

func TestVerifyContractPersistsTranslationWithIntegrityAndCoverageGaps(t *testing.T) {
	binding, c := formalFixture(t)
	client := &stubLLM{reply: translationReply(t, "int main(void) { return 0; }")}
	fact, out := VerifyContract(context.Background(), client, binding, c, 0)
	if client.calls != 1 || out.Status != StatusSandboxUnavailable || fact.Status == "success" || out.Translation == nil {
		t.Fatalf("translation presented as verification: %+v %+v calls=%d", fact, out, client.calls)
	}
	if len(fact.CoverageGaps) < 2 || !strings.Contains(strings.Join(fact.CoverageGaps, " "), "not independently validated") {
		t.Fatalf("missing semantic and execution gaps: %+v", fact.CoverageGaps)
	}
	var persisted artifacts.ToolFact
	path := filepath.Join(binding.RunDir, filepath.FromSlash(fact.ArtifactRef))
	if fact.ArtifactRef == "" {
		t.Fatal("persisted fact has no artifact reference")
	}
	if err := runfs.ReadJSON(path, &persisted); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(schema.TrustIRToolV1, body); err != nil {
		t.Fatalf("formal ToolFact does not match the canonical protocol: %v", err)
	}
	if _, err := contracts.LoadToolFact(fact.ArtifactRef, binding); err != nil {
		t.Fatalf("persisted formal ToolFact is not usable evidence: %v", err)
	}
	if persisted.FactID != fact.FactID || persisted.ContentSHA256 == "" || persisted.ContentSHA256 != artifacts.ToolFactContentSHA256(persisted) {
		t.Fatalf("persisted integrity mismatch: %+v", persisted)
	}
}

func TestVerifyContractRefusesStaleOrEscapedSourceBeforeCallingModel(t *testing.T) {
	for _, kind := range []string{"changed", "escape", "symlink", "wrong scope"} {
		t.Run(kind, func(t *testing.T) {
			binding, c := formalFixture(t)
			switch kind {
			case "changed":
				if err := os.WriteFile(filepath.Join(binding.RepoRoot, "a.c"), []byte("int f(int x) { return x - 1; }\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "escape":
				c.Subjects[0].Path = "../outside.c"
				c.DefinitionHash = contracts.DefinitionHash(c)
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside.c")
				if err := os.WriteFile(outside, []byte("int f(int x) { return x + 1; }\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(binding.RepoRoot, "a.c")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(binding.RepoRoot, "a.c")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "wrong scope":
				c.Scope.Commit = "another-revision"
			}
			client := &stubLLM{}
			_, out := VerifyContract(context.Background(), client, binding, c, 0)
			if client.calls != 0 || out.Status != StatusInvalidSource {
				t.Fatalf("invalid source sent to model: calls=%d out=%+v", client.calls, out)
			}
		})
	}
}

func TestVerifyContractPersistenceFailureIsReported(t *testing.T) {
	binding, c := formalFixture(t)
	if err := os.WriteFile(runfs.VerifierDir(binding.RunDir), []byte("blocks directory creation"), 0600); err != nil {
		t.Fatal(err)
	}
	client := &stubLLM{reply: translationReply(t, "int main(void) { return 0; }")}
	fact, out := VerifyContract(context.Background(), client, binding, c, 0)
	if out.Status != StatusPersistFailed || fact.Status != "error" || fact.ArtifactRef != "" || !strings.Contains(fact.Error, "persist formal ToolFact") {
		t.Fatalf("failed write claimed persisted evidence: fact=%+v out=%+v", fact, out)
	}
	if fact.ContentSHA256 != artifacts.ToolFactContentSHA256(fact) {
		t.Fatal("failure record has stale integrity digest")
	}
}

type slowBlockingLLM struct{}

func (slowBlockingLLM) Generate(ctx context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	<-ctx.Done()
	return llm.GenerateResponse{}, ctx.Err()
}

func TestVerifyContractTranslationTimeoutDegradesCleanly(t *testing.T) {
	orig := translateTimeout
	translateTimeout = 20 * time.Millisecond
	defer func() { translateTimeout = orig }()
	binding, c := formalFixture(t)
	fact, out := VerifyContract(context.Background(), slowBlockingLLM{}, binding, c, 0)
	if out.Status != StatusTimeout || fact.Status != "error" || fact.ArtifactRef == "" {
		t.Fatalf("timeout not recorded and persisted: fact=%+v out=%+v", fact, out)
	}
}

func TestValidateHarnessSourceIsOnlyALexicalScreen(t *testing.T) {
	for _, source := range []string{"", `#include <unistd.h>`, `int main(void) { system("id"); }`, strings.Repeat("x", maxHarnessBytes+1)} {
		if out := ExecuteHarness(context.Background(), TranslationSpec{Applicable: true, CSource: source}); out.Status != StatusUnsafeHarness {
			t.Fatalf("unsuitable translation not rejected: %+v", out)
		}
	}
	if err := validateHarnessSource("static int syscall_storage_obj_open(int x) { return x; }"); err != nil {
		t.Fatalf("benign suffix rejected: %v", err)
	}
	if DetectBackend() != BackendNone {
		t.Fatal("host tool availability was mistaken for an isolated executor")
	}
}
