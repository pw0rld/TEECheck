package runvalidate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func contractBundle(t *testing.T) (string, artifacts.CasePack, artifacts.VerificationMemo) {
	t.Helper()
	dir := validBundle(t)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "a.c"), []byte("int load(void) { return 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := runfs.LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.RepoURL, m.Commit, m.LocalPath = "fixture", "rev", source
	m.Scope = runfs.BuildScope(m.RepoURL, m.Commit, source)
	if err := runfs.WriteJSON(runfs.ManifestPath(dir), m); err != nil {
		t.Fatal(err)
	}
	draft := artifacts.CaseInvariantV2{InvariantID: "inv-1", Origin: "planner", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, Preconditions: []string{"a caller reaches load"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "load must enforce the policy"}, SecurityEffect: "unauthorized operation"}
	c, diags, err := contracts.Bind(draft, contracts.BindingContext{RunDir: dir, RepoRoot: source, Scope: m.Scope})
	if err != nil || len(diags) > 0 {
		t.Fatalf("contract bind: %v %+v", err, diags)
	}
	pack := artifacts.CasePack{CaseID: "case-1", ContractRequired: true, CaseInvariants: []artifacts.CaseInvariantV2{c}}
	memo := artifacts.VerificationMemo{CaseID: pack.CaseID, InvariantAssessments: []artifacts.InvariantAssessment{{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID, DefinitionHash: c.DefinitionHash, Scope: c.Scope, Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "no registered query", VerificationBasis: "unresolved"}}}
	for path, value := range map[string]any{
		filepath.Join(runfs.CasePacksDir(dir), "case-001.json"):       pack,
		filepath.Join(runfs.ExpertDir(dir), "hypothesis-001.json"):    artifacts.Hypothesis{CaseID: pack.CaseID},
		filepath.Join(runfs.ChallengerDir(dir), "challenge-001.json"): artifacts.Challenge{CaseID: pack.CaseID},
		filepath.Join(runfs.VerifierDir(dir), "verify-001.json"):      memo,
	} {
		if err := runfs.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := runfs.WriteText(filepath.Join(runfs.ArbiterPacketsDir(dir), "review-001-contract-001.md"), "review"); err != nil {
		t.Fatal(err)
	}
	f := artifacts.Findings{SchemaVersion: "teecheck.findings.v2", RunID: "run-1", Findings: []artifacts.FindingItem{{FindingID: "case-1:inv-1", SliceID: pack.CaseID, InvariantID: c.InvariantID, InvariantDefinitionHash: c.DefinitionHash, Status: "needs_review", Severity: "medium", Confidence: "low", Summary: "needs evidence", VerificationBasis: "unresolved"}}}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), f); err != nil {
		t.Fatal(err)
	}
	return dir, pack, memo
}

func TestRunValidate_RejectsCrossContractFinding(t *testing.T) {
	dir, _, _ := contractBundle(t)
	var f artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(dir), &f); err != nil {
		t.Fatal(err)
	}
	f.Findings[0].InvariantID = "another-case-invariant"
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), f); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "finding_contract")
}

func TestRunValidate_RejectsDuplicateAssessments(t *testing.T) {
	dir, _, memo := contractBundle(t)
	memo.InvariantAssessments = append(memo.InvariantAssessments, memo.InvariantAssessments[0])
	if err := runfs.WriteJSON(filepath.Join(runfs.VerifierDir(dir), "verify-001.json"), memo); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "contract_assessment")
}

func TestRunValidate_RejectsContractScopeDrift(t *testing.T) {
	dir, pack, _ := contractBundle(t)
	pack.CaseInvariants[0].Scope.Commit = "other-revision"
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(dir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "case_contract")
}

func TestRunValidate_AcceptsBoundUnresolvedContract(t *testing.T) {
	dir, _, _ := contractBundle(t)
	if result := Validate(dir); !result.Valid {
		t.Fatalf("valid typed bundle rejected: %+v", result.Issues)
	}
}

func TestRunValidate_RejectsLegacyUpdatesForTypedContract(t *testing.T) {
	dir, _, memo := contractBundle(t)
	memo.InvariantUpdates = []artifacts.InvariantStatusUpdate{{}}
	if err := runfs.WriteJSON(filepath.Join(runfs.VerifierDir(dir), "verify-001.json"), memo); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "legacy_invariant_updates")
}

func TestRunValidate_UnformalizedCaseCannotBePositive(t *testing.T) {
	dir, pack, memo := contractBundle(t)
	pack.CaseInvariants = nil
	memo.InvariantAssessments = nil
	for path, v := range map[string]any{filepath.Join(runfs.CasePacksDir(dir), "case-001.json"): pack, filepath.Join(runfs.VerifierDir(dir), "verify-001.json"): memo} {
		if err := runfs.WriteJSON(path, v); err != nil {
			t.Fatal(err)
		}
	}
	var f artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(dir), &f); err != nil {
		t.Fatal(err)
	}
	f.Findings[0].InvariantID = ""
	f.Findings[0].InvariantDefinitionHash = ""
	f.Findings[0].Status = "likely_issue"
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), f); err != nil {
		t.Fatal(err)
	}
	assertIssue(t, Validate(dir), "finding_contract")
	f.Findings[0].Status = "needs_review"
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), f); err != nil {
		t.Fatal(err)
	}
	if result := Validate(dir); !result.Valid {
		t.Fatalf("unformalized needs_review should remain readable: %+v", result.Issues)
	}
}
