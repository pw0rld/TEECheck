package reverify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func setupRecheck(t *testing.T) (config.Config, artifacts.CaseInvariantV2, string) {
	t.Helper()
	root := t.TempDir()
	oldRoot := filepath.Join(root, "old")
	fixedRoot := filepath.Join(root, "fixed")
	for _, p := range []string{oldRoot, fixedRoot} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(oldRoot, "a.c"), []byte("int load(void) { return 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixedRoot, "a.c"), []byte("// new header\n\nint load(void) { return 2; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := artifacts.CaseInvariantV2{Origin: "planner", LeadRef: "old-lead", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, Preconditions: []string{"valid input"}, RequiredProperty: artifacts.ContractProperty{Kind: "field_propagation", Statement: "copy version", Destination: "key.version"}, SecurityEffect: "controls accepted version"}
	old, _, err := contracts.Bind(c, contracts.BindingContext{RepoRoot: oldRoot, Scope: artifacts.ScannedScope{RepoURL: "fixture", Commit: "old"}})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "contract.json")
	if err = runfs.WriteJSON(input, old); err != nil {
		t.Fatal(err)
	}
	return config.Config{ContractPath: input, LocalPath: fixedRoot, RepoURL: "fixture", Commit: "fixed", OutputDir: filepath.Join(root, "contract-rechecks")}, old, root
}
func unresolved(c artifacts.CaseInvariantV2) artifacts.InvariantAssessment {
	return artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID, DefinitionHash: c.DefinitionHash, Scope: c.Scope, Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "No registered executor exists", VerificationBasis: "unavailable"}
}
func TestReverify_StripsVulnerableWitnessBeforeFixedBinding(t *testing.T) {
	cfg, old, _ := setupRecheck(t)
	calls := 0
	out, err := RunWithAssessment(context.Background(), cfg, func(_ context.Context, passed config.Config, c artifacts.CaseInvariantV2, b contracts.BindingContext) (artifacts.InvariantAssessment, error) {
		calls++
		if c.DefinitionHash != old.DefinitionHash || c.Scope.Commit != "fixed" || c.Subjects[0].StartLine != 3 || c.LeadRef != "" || c.Origin != "reverify" {
			t.Fatalf("bad fixed binding: %+v", c)
		}
		if c.Subjects[0].ContentSHA256 == old.Subjects[0].ContentSHA256 {
			t.Fatal("vulnerable source hash leaked")
		}
		for _, r := range c.EvidenceRefs {
			if r.Kind != "source" || r.StartLine != 3 {
				t.Fatalf("old witness leaked: %+v", r)
			}
		}
		if passed.RunDir != b.RunDir {
			t.Fatal("assessment does not use isolated output")
		}
		return unresolved(c), nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("reverify calls=%d err=%v", calls, err)
	}
	if _, err := os.Stat(filepath.Join(out, "assessment.json")); err != nil {
		t.Fatal(err)
	}
}
func TestReverify_DoesNotWriteToKnowledgeStore(t *testing.T) {
	cfg, _, root := setupRecheck(t)
	for _, name := range []string{"knowledge", "feedback", "runs"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	assess := func(_ context.Context, _ config.Config, c artifacts.CaseInvariantV2, _ contracts.BindingContext) (artifacts.InvariantAssessment, error) {
		return unresolved(c), nil
	}
	first, err := RunWithAssessment(context.Background(), cfg, assess)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunWithAssessment(context.Background(), cfg, assess)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused output directory")
	}
	for _, name := range []string{"knowledge", "feedback", "runs"} {
		entries, err := os.ReadDir(filepath.Join(root, name))
		if err != nil || len(entries) != 0 {
			t.Fatalf("wrote into %s", name)
		}
	}
	cfg.OutputDir = filepath.Join(root, "knowledge", "rechecks")
	if _, err := RunWithAssessment(context.Background(), cfg, assess); err == nil {
		t.Fatal("allowed knowledge output")
	}
}
func TestReverify_RejectsOutputInOriginalRun(t *testing.T) {
	cfg, _, root := setupRecheck(t)
	run := filepath.Join(root, "original-run")
	if err := os.MkdirAll(run, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "00_manifest.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(cfg.ContractPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ContractPath = filepath.Join(run, "contract.json")
	if err = os.WriteFile(cfg.ContractPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.OutputDir = filepath.Join(run, "rechecks")
	if _, err := RunWithAssessment(context.Background(), cfg, nil); err == nil {
		t.Fatal("allowed original-run output")
	}
}
