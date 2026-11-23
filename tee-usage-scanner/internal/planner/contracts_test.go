package planner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
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

func TestAcceptedContractCopiesRejectsModelGroundingClaims(t *testing.T) {
	_, _, _, _, draft := closingContractFixture(t)
	draft.Grounding = "source_bound"
	draft.InvariantID = "model-claimed-id"
	draft.DefinitionHash = contracts.DefinitionHash(draft)
	if got, rejected := acceptedContractCopies([]artifacts.CaseInvariantV2{draft}, nil); len(got) != 0 || rejected != 1 {
		t.Fatalf("model metadata substituted for machine acceptance: %+v, rejected=%d", got, rejected)
	}
}

func TestAcceptedContractCopiesRestoresMachineAnchors(t *testing.T) {
	cfg, _, _, _, raw := closingContractFixture(t)
	accepted, diagnostics, err := contracts.Bind(raw, contracts.BindingContext{
		RepoRoot: cfg.RepoRoot, Scope: runfs.BuildScope("fixture", "rev", cfg.RepoRoot),
	})
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("bind fixture: %v, diagnostics=%+v", err, diagnostics)
	}
	draft := cloneContractsSlice([]artifacts.CaseInvariantV2{accepted})[0]
	draft.InvariantID = "model-replacement"
	draft.Subjects[0].ContentSHA256 = "model-replacement"
	draft.EvidenceRefs = nil
	got, rejected := acceptedContractCopies([]artifacts.CaseInvariantV2{draft}, []artifacts.CaseInvariantV2{accepted})
	if rejected != 0 || len(got) != 1 || !reflect.DeepEqual(got[0], accepted) {
		t.Fatalf("machine anchors were replaced by echoed model fields: %+v, rejected=%d", got, rejected)
	}
}

func TestInvestigationAssemblyCannotBindNewContractDrafts(t *testing.T) {
	cfg, _, _, _, draft := closingContractFixture(t)
	cfg.StrictContractExit = true
	draft.Grounding = "source_bound"
	draft.InvariantID = "model-claimed-id"
	draft.DefinitionHash = contracts.DefinitionHash(draft)
	raw := []map[string]any{{
		"twe_ids":         []string{"TWE-GUARD-004"},
		"case_invariants": []artifacts.CaseInvariantV2{draft},
	}}
	invs, packs, diagnostics := processInvestigations(raw, cfg, NewState(cfg.RunID), nil)
	if len(invs) != 1 || len(packs) != 1 || len(packs[0].CaseInvariants) != 0 {
		t.Fatalf("unaccepted contract reached final investigation pack: %+v", packs)
	}
	reported := false
	for _, diagnostic := range diagnostics {
		reported = reported || strings.Contains(diagnostic.Error, "not accepted during the planner loop")
	}
	if !reported {
		t.Fatalf("omitted draft has no diagnostic: %+v", diagnostics)
	}
	for _, path := range []string{runfs.AuditLeadsPath(cfg.RunDir), filepath.Join(runfs.PlannerDir(cfg.RunDir), "contracts")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("final assembly wrote contract or lead state at %s: %v", path, err)
		}
	}
}
