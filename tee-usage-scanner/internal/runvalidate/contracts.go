package runvalidate

import (
	"fmt"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type validatedCase struct {
	pack        artifacts.CasePack
	contracts   map[string]artifacts.CaseInvariantV2
	assessments map[string]artifacts.InvariantAssessment
}

// Contract references are resolved inside their own case. The same logical
// invariant may appear in another case, but its assessment is never borrowed.
func validateContracts(runDir string, m artifacts.Manifest, add func(string, string, string, ...any)) {
	paths, _ := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	byCase := map[string]validatedCase{}
	ctx := contracts.BindingContext{RunDir: runDir, RepoRoot: m.LocalPath, Scope: m.Scope}
	for i, path := range paths {
		var pack artifacts.CasePack
		if runfs.ReadJSON(path, &pack) != nil || pack.CaseID == "" {
			continue
		}
		if _, duplicate := byCase[pack.CaseID]; duplicate {
			add("case_contract", path, "duplicate case_id %q", pack.CaseID)
			continue
		}
		state := validatedCase{pack: pack, contracts: map[string]artifacts.CaseInvariantV2{}, assessments: map[string]artifacts.InvariantAssessment{}}
		memoPath := filepath.Join(runfs.VerifierDir(runDir), fmt.Sprintf("verify-%03d.json", i+1))
		var memo artifacts.VerificationMemo
		_ = runfs.ReadJSON(memoPath, &memo)
		if len(pack.CaseInvariants) > 0 {
			if len(memo.InvariantUpdates) > 0 {
				add("legacy_invariant_updates", memoPath, "typed contracts cannot consume case-level legacy invariant updates")
			}
			for _, c := range pack.CaseInvariants {
				if _, duplicate := state.contracts[c.InvariantID]; duplicate {
					add("case_contract", path, "duplicate invariant_id %q in this case", c.InvariantID)
					continue
				}
				state.contracts[c.InvariantID] = c
				if c.Scope.RepoURL != m.Scope.RepoURL || c.Scope.Commit != m.Scope.Commit || c.Scope.Hash != m.Scope.Hash {
					add("case_contract", path, "contract %q does not identify this exact run scope", c.InvariantID)
				}
				if err := contracts.Validate(c, ctx); err != nil {
					add("case_contract", path, "contract %q: %v", c.InvariantID, err)
				}
			}
		}
		for _, a := range memo.InvariantAssessments {
			c, exists := state.contracts[a.InvariantID]
			if !exists {
				add("contract_assessment", memoPath, "assessment %q has no contract in its own case", a.InvariantID)
				continue
			}
			if _, duplicate := state.assessments[a.InvariantID]; duplicate {
				add("contract_assessment", memoPath, "duplicate assessment for %q", a.InvariantID)
				continue
			}
			state.assessments[a.InvariantID] = a
			if err := contracts.ValidateAssessment(a, c, ctx); err != nil {
				add("contract_assessment", memoPath, "assessment %q: %v", a.InvariantID, err)
			}
		}
		for id := range state.contracts {
			if _, exists := state.assessments[id]; !exists {
				add("contract_assessment", memoPath, "contract %q has no assessment in its own case", id)
			}
		}
		byCase[pack.CaseID] = state
	}
	var findings artifacts.Findings
	if runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings) != nil {
		return
	}
	seen := map[string]bool{}
	for _, f := range findings.Findings {
		path := runfs.ArbiterFindingsPath(runDir)
		state, exists := byCase[f.SliceID]
		if !exists {
			if f.InvariantID != "" || f.InvariantDefinitionHash != "" {
				add("finding_contract", path, "finding %q names a contract outside its own case", f.FindingID)
			}
			continue
		}
		if len(state.contracts) == 0 {
			if f.InvariantID != "" || f.InvariantDefinitionHash != "" {
				add("finding_contract", path, "finding %q references an undefined contract", f.FindingID)
			}
			if state.pack.ContractRequired && f.Status != "needs_review" {
				add("finding_contract", path, "unformalized case %q may only produce needs_review", f.SliceID)
			}
			continue
		}
		c, exists := state.contracts[f.InvariantID]
		if !exists || f.InvariantDefinitionHash != c.DefinitionHash {
			add("finding_contract", path, "finding %q has no matching contract ID and definition hash in its own case", f.FindingID)
			continue
		}
		key := f.SliceID + "\x00" + f.InvariantID
		if seen[key] {
			add("finding_contract", path, "multiple findings reference case/contract %q", key)
		}
		seen[key] = true
		a, exists := state.assessments[f.InvariantID]
		if !exists {
			add("finding_contract", path, "finding %q has no matching assessment", f.FindingID)
			continue
		}
		if f.VerificationBasis != a.VerificationBasis {
			add("finding_contract", path, "finding %q verification_basis differs from its assessment", f.FindingID)
		}
		switch f.Status {
		case "confirmed_candidate":
			if a.Assessment != "violated" || !a.AttackChainComplete {
				add("finding_contract", path, "confirmed finding %q lacks a violated assessment and complete attack chain", f.FindingID)
			}
		case "likely_issue":
			allowed := a.Assessment == "violated" || (a.Assessment == "unresolved" && a.ReasonCode == "no_registered_query" && a.VerificationBasis == "source_corroborated_no_query" && a.SourceCorroborated && a.PreconditionsSatisfied && len(a.Witness) > 0 && len(a.Contradictions) == 0 && len(a.MissingEvidence) == 0)
			if !allowed {
				add("finding_contract", path, "likely finding %q lacks a supported contract assessment", f.FindingID)
			}
		case "no_issue_observed":
			if a.Assessment != "satisfied" {
				add("finding_contract", path, "negative finding %q lacks a satisfied assessment", f.FindingID)
			}
		}
	}
}
