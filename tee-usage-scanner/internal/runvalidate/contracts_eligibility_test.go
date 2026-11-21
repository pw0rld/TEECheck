package runvalidate

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func writeEligibleFinding(t *testing.T, dir string, pack artifacts.CasePack, memo artifacts.VerificationMemo, status string, expert, challenger []artifacts.ContractReview) {
	t.Helper()
	for path, value := range map[string]any{
		filepath.Join(runfs.CasePacksDir(dir), "case-001.json"):       pack,
		filepath.Join(runfs.ExpertDir(dir), "hypothesis-001.json"):    artifacts.Hypothesis{CaseID: pack.CaseID, ContractReviews: expert},
		filepath.Join(runfs.ChallengerDir(dir), "challenge-001.json"): artifacts.Challenge{CaseID: pack.CaseID, ContractReviews: challenger},
		filepath.Join(runfs.VerifierDir(dir), "verify-001.json"):      memo,
	} {
		if err := runfs.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	c, a := pack.CaseInvariants[0], memo.InvariantAssessments[0]
	f := artifacts.Findings{SchemaVersion: "teecheck.findings.v2", RunID: "run-1", Findings: []artifacts.FindingItem{{FindingID: pack.CaseID + ":" + c.InvariantID, SliceID: pack.CaseID, InvariantID: c.InvariantID, InvariantDefinitionHash: c.DefinitionHash, Status: status, Severity: "medium", Confidence: "medium", Summary: "Review the bound contract", VerificationBasis: a.VerificationBasis}}}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), f); err != nil {
		t.Fatal(err)
	}
}

func TestRunValidate_LikelyRequiresIndependentContractReviews(t *testing.T) {
	for _, mode := range []string{"supported", "missing expert", "missing challenger", "contradicted", "duplicate", "unanchored", "unbound contract"} {
		t.Run(mode, func(t *testing.T) {
			dir, pack, memo := contractBundle(t)
			c := pack.CaseInvariants[0]
			a := &memo.InvariantAssessments[0]
			a.SourceCorroborated, a.PreconditionsSatisfied = true, true
			a.Witness, a.EvidenceRefs = c.Subjects, c.EvidenceRefs
			a.VerificationBasis = "source_corroborated_no_query"
			r := artifacts.ContractReview{InvariantID: c.InvariantID, Position: "supported", Reason: "The source supports the concern", PreconditionsSatisfied: true, AttackChainComplete: true, Witness: c.Subjects}
			expert, challenger := []artifacts.ContractReview{r}, []artifacts.ContractReview{r}
			switch mode {
			case "missing expert":
				expert = nil
			case "missing challenger":
				challenger = nil
			case "contradicted":
				challenger[0].Position = "contradicted"
				challenger[0].CounterEvidence = []string{"A guard exists"}
			case "duplicate":
				challenger = append(challenger, r)
			case "unanchored":
				challenger[0].Witness = nil
			case "unbound contract":
				pack.CaseInvariants[0].Grounding = "unresolved"
			}
			writeEligibleFinding(t, dir, pack, memo, "likely_issue", expert, challenger)
			report := Validate(dir)
			if mode == "supported" {
				if !report.Valid {
					t.Fatalf("supported finding rejected: %+v", report.Issues)
				}
			} else {
				assertIssue(t, report, "finding_contract")
			}
		})
	}
}

func TestRunValidate_ConfirmedRequiresIndependentCompleteChain(t *testing.T) {
	dir, pack, memo := contractBundle(t)
	c := &pack.CaseInvariants[0]
	c.VerificationQueries = []artifacts.ContractQuery{{Backend: "test", Operation: "test.local"}}
	c.DefinitionHash = contracts.DefinitionHash(*c)
	a := &memo.InvariantAssessments[0]
	a.DefinitionHash = c.DefinitionHash
	a.Assessment, a.ReasonCode, a.Reason = "violated", "query_violated", "The registered query establishes a local violation"
	a.VerificationBasis, a.QueryOperation = "registered_query", "test.local"
	a.SourceCorroborated, a.PreconditionsSatisfied, a.AttackChainComplete = true, true, true
	a.Witness, a.EvidenceRefs = c.Subjects, c.EvidenceRefs
	result, _ := json.Marshal(map[string]string{"assessment": a.Assessment, "contract_hash": a.DefinitionHash, "reason_code": a.ReasonCode})
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "eligibility-proof", Tool: "test", Operation: a.QueryOperation, RepoCommit: c.Scope.Commit, Status: "success", Result: result}
	ref, err := trustirfacts.Persist(dir, fact)
	if err != nil {
		t.Fatal(err)
	}
	a.EvidenceRefs = append(append([]artifacts.ContractEvidenceRef{}, a.EvidenceRefs...), artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: ref})
	r := artifacts.ContractReview{InvariantID: c.InvariantID, Position: "supported", Reason: "The source supports the concern", PreconditionsSatisfied: true, AttackChainComplete: false, Witness: c.Subjects}
	writeEligibleFinding(t, dir, pack, memo, "confirmed_candidate", []artifacts.ContractReview{r}, []artifacts.ContractReview{r})
	assertIssue(t, Validate(dir), "finding_contract")
	r.AttackChainComplete = true
	writeEligibleFinding(t, dir, pack, memo, "confirmed_candidate", []artifacts.ContractReview{r}, []artifacts.ContractReview{r})
	if report := Validate(dir); !report.Valid {
		t.Fatalf("complete chain rejected: %+v", report.Issues)
	}
}
