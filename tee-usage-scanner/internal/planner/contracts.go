package planner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func bindPlannerContracts(raw []artifacts.CaseInvariantV2, cfg RunConfig) ([]artifacts.CaseInvariantV2, []artifacts.RoundError) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []artifacts.CaseInvariantV2
	var problems []artifacts.RoundError
	problem := func(id string, err error) {
		problems = append(problems, artifacts.RoundError{Round: -1, Action: "formalize_invariant:" + id, Error: err.Error()})
	}
	m, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		problem("manifest", err)
		return nil, problems
	}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: cfg.RepoRoot, Scope: m.Scope}
	if binding.Scope.Commit == "" {
		binding.Scope = runfs.BuildScope(m.RepoURL, m.Commit, cfg.RepoRoot)
	}
	leads, err := contractLeads(cfg)
	if err != nil {
		problem("lead", err)
		return nil, problems
	}
	seen := map[string]string{}
	for _, c := range raw {
		c.Origin = "planner"
		// Model-local names such as inv-1 are routinely reused by later
		// samples. Machine identity follows the actual logical definition.
		c.InvariantID = "case-inv-" + contracts.DefinitionHash(c)
		lead, ok := leads[c.LeadRef]
		if !ok {
			problem(c.InvariantID, fmt.Errorf("contract must cite an audit lead opened in this planner sample"))
			continue
		}
		if !contractSharesLead(c, lead) {
			problem(c.InvariantID, fmt.Errorf("contract subjects do not include the referenced lead's target"))
			continue
		}
		bound, diagnostics, err := contracts.Bind(c, binding)
		if err != nil {
			problem(c.InvariantID, err)
			continue
		}
		for _, d := range diagnostics {
			problem(bound.InvariantID, fmt.Errorf("%s: %s", d.Code, d.Message))
		}
		if old, exists := seen[bound.InvariantID]; exists && old != bound.DefinitionHash {
			problem(bound.InvariantID, fmt.Errorf("contract id reused for a different definition"))
			continue
		}
		seen[bound.InvariantID] = bound.DefinitionHash
		path := filepath.Join(runfs.PlannerDir(cfg.RunDir), "contracts", bound.DefinitionHash+".json")
		if err := runfs.WriteJSON(path, bound); err != nil {
			problem(bound.InvariantID, err)
			continue
		}
		out = append(out, bound)
	}
	return contracts.MergeAll(nil, out), problems
}

func plannerContractPacks(raw []artifacts.CaseInvariantV2, cfg RunConfig) ([]artifacts.CasePack, []artifacts.RoundError) {
	bound, errs := bindPlannerContracts(raw, cfg)
	var packs []artifacts.CasePack
	for _, c := range bound {
		p := artifacts.CasePack{SchemaVersion: "teecheck.case_pack.v1", CaseID: "contract:" + c.InvariantID, Focus: cfg.Profile.Focus,
			Priority: "medium", Category: "boundary", ContractRequired: true, CaseInvariants: []artifacts.CaseInvariantV2{c},
			RelatedTWEs: c.RelatedTWEs, WhySelected: []string{c.RequiredProperty.Statement}}
		for _, s := range c.Subjects {
			p.TargetFiles = unionStrings(p.TargetFiles, []string{s.Path})
			p.TargetSymbols = unionStrings(p.TargetSymbols, []string{s.Symbol})
		}
		if c.Grounding != "source_bound" {
			p.CoverageGaps = append(p.CoverageGaps, "Contract subjects could not be uniquely bound.")
		}
		packs = append(packs, p)
	}
	return packs, errs
}

func contractLeads(cfg RunConfig) (map[string]artifacts.AuditLead, error) {
	f, err := os.Open(runfs.AuditLeadsPath(cfg.RunDir))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	result := map[string]artifacts.AuditLead{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var lead artifacts.AuditLead
		if err := json.Unmarshal(scanner.Bytes(), &lead); err != nil {
			return nil, err
		}
		if lead.RunID == cfg.RunID && lead.SampleIndex == cfg.SampleIndex {
			result[lead.LeadID] = lead
		}
	}
	return result, scanner.Err()
}

func contractSharesLead(c artifacts.CaseInvariantV2, lead artifacts.AuditLead) bool {
	for _, s := range c.Subjects {
		for _, id := range lead.TargetSymbolIDs {
			if s.SymbolID != "" && s.SymbolID == id {
				return true
			}
			name := string(id)
			if name == s.Path {
				return true
			}
			if name == s.Path+"::"+s.Symbol {
				return true
			}
			parts := strings.SplitN(name, ":", 4)
			if len(parts) == 4 && parts[1] == s.Path && (parts[3] == s.Symbol || strings.HasPrefix(parts[3], s.Symbol+"(")) {
				return true
			}
		}
	}
	return false
}
