package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestContractSharesLeadAcceptsObservedTreeOnlyPath(t *testing.T) {
	c := artifacts.CaseInvariantV2{Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}}
	if !contractSharesLead(c, artifacts.AuditLead{TargetSymbolIDs: []artifacts.SymbolID{"a.c"}}) {
		t.Fatal("valid file-scoped lead rejected")
	}
}

func TestPlannerContractIDsDoNotCollideAcrossSamples(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("int load(void) { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := artifacts.Manifest{RunID: "test", RepoURL: "fixture", Commit: "rev", Scope: runfs.BuildScope("fixture", "rev", root)}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), m); err != nil {
		t.Fatal(err)
	}
	for sample := 0; sample < 2; sample++ {
		if err := appendAuditLead(runfs.AuditLeadsPath(run), artifacts.AuditLead{LeadID: "lead", RunID: "test", SampleIndex: sample, TargetSymbolIDs: []artifacts.SymbolID{"a.c::load"}}); err != nil {
			t.Fatal(err)
		}
	}
	raw := artifacts.CaseInvariantV2{InvariantID: "inv-1", LeadRef: "lead", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, Preconditions: []string{"called"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "first property", TargetFields: []string{"first"}}, SecurityEffect: "decision"}
	a, errs := bindPlannerContracts([]artifacts.CaseInvariantV2{raw}, RunConfig{RunID: "test", RunDir: run, RepoRoot: root})
	if len(errs) > 0 || len(a) != 1 {
		t.Fatalf("first: %v %+v", errs, a)
	}
	raw.RequiredProperty.TargetFields = []string{"second"}
	b, errs := bindPlannerContracts([]artifacts.CaseInvariantV2{raw}, RunConfig{RunID: "test", RunDir: run, RepoRoot: root, SampleIndex: 1})
	if len(errs) > 0 || len(b) != 1 || a[0].InvariantID == b[0].InvariantID {
		t.Fatalf("second: %v %+v", errs, b)
	}
}
