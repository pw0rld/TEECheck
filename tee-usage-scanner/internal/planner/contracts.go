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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func bindPlannerContracts(raw []artifacts.CaseInvariantV2, cfg RunConfig) ([]artifacts.CaseInvariantV2, []artifacts.RoundError) {
	return bindPlannerContractsWithState(raw, cfg, nil, nil, nil, nil)
}

// bindPlannerContractsWithState validates, source-binds, and persists NEW draft
// contracts to 04_planner/contracts/<hash>.json, updating referenced AuditLeads
// to LeadStateFormalized in BOTH 04_planner/audit_leads.jsonl and in-memory
// state.AuditLeads. Already-accepted contracts in state.Contracts are preserved
// without re-running draft source-window checks so partial reads of long
// functions never lose previously bound full-function anchors.
func bindPlannerContractsWithState(
	raw []artifacts.CaseInvariantV2,
	cfg RunConfig,
	state *PlannerState,
	observed *ObservationSet,
	executedToolFactRefs []string,
	currentRound *artifacts.RoundRecord,
) ([]artifacts.CaseInvariantV2, []artifacts.RoundError) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []artifacts.CaseInvariantV2
	var problems []artifacts.RoundError
	roundNo := -1
	if currentRound != nil && currentRound.Round > 0 {
		roundNo = currentRound.Round
	}
	problem := func(id string, err error) {
		problems = append(problems, artifacts.RoundError{
			Round:  roundNo,
			Action: "formalize_invariant:" + id,
			Error:  err.Error(),
		})
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

	leadsByID := map[string]artifacts.AuditLead{}
	leadIndexInState := map[string]int{}
	acceptedByHash := map[string]artifacts.CaseInvariantV2{}
	if state != nil {
		for i, lead := range state.AuditLeads {
			if lead.RunID == cfg.RunID && lead.SampleIndex == cfg.SampleIndex {
				leadsByID[lead.LeadID] = lead
				leadIndexInState[lead.LeadID] = i
			}
		}
		for _, acc := range state.Contracts {
			if acc.Grounding == "source_bound" && acc.DefinitionHash != "" {
				acceptedByHash[acc.DefinitionHash] = acc
			}
		}
	}
	if diskLeads, derr := contractLeads(cfg); derr == nil {
		for id, lead := range diskLeads {
			if _, exists := leadsByID[id]; !exists {
				leadsByID[id] = lead
			}
		}
	} else if len(leadsByID) == 0 {
		problem("lead", derr)
		return nil, problems
	}

	var sources []formalizationSource
	if state != nil && observed != nil {
		snapshot := *state
		if currentRound != nil {
			snapshot.Rounds = append(append([]artifacts.RoundRecord(nil), state.Rounds...), *currentRound)
		}
		sources = observedSourceWindows(&snapshot, *observed, observationlimits.MaxBytes)
	}

	seen := map[string]string{}
	for _, c := range raw {
		defHash := contracts.DefinitionHash(c)
		if existing, ok := acceptedByHash[defHash]; ok {
			out = append(out, existing)
			continue
		}
		c.Origin = "planner"
		c.InvariantID = "case-inv-" + defHash
		lead, ok := leadsByID[c.LeadRef]
		if !ok {
			problem(c.InvariantID, fmt.Errorf("contract must cite an audit lead opened in this planner sample"))
			continue
		}
		if !contractSharesLead(c, lead) {
			problem(c.InvariantID, fmt.Errorf("contract subjects do not include the referenced lead's target"))
			continue
		}
		c.EvidenceRefs = includeLeadTaintRefs(c.EvidenceRefs, lead)

		var observationRefs []artifacts.ContractEvidenceRef
		var toolFactRefs []artifacts.ContractEvidenceRef
		var sourceRefs []artifacts.ContractEvidenceRef
		if state != nil && observed != nil {
			refFailed := false
			for _, ref := range c.EvidenceRefs {
				switch ref.Kind {
				case "observation":
					if !strings.HasPrefix(ref.Ref, "obs:") || !observed.Observed(ref.Ref) {
						problem(c.InvariantID, fmt.Errorf("reference %q is not a successful observation in this sample", ref.Ref))
						refFailed = true
						break
					}
					observationRefs = appendUniqueEvidenceRef(observationRefs, artifacts.ContractEvidenceRef{Kind: "observation", Ref: ref.Ref})
				case "tool_fact":
					fact, path, ferr := resolveLeadFactRef(cfg, *observed, executedToolFactRefs, ref.Ref)
					if ferr != nil || fact == nil {
						if ferr == nil {
							ferr = fmt.Errorf("tool_fact reference must name an executed ToolFact")
						}
						problem(c.InvariantID, ferr)
						refFailed = true
						break
					}
					resolved := ref
					resolved.Ref = path
					toolFactRefs = appendUniqueEvidenceRef(toolFactRefs, resolved)
				default:
					sourceRefs = append(sourceRefs, ref)
				}
			}
			if refFailed {
				continue
			}
			if cfg.StrictContractExit {
				c.EvidenceRefs = sourceRefs
				cand := formalizationCandidate{Leads: []artifacts.AuditLead{lead}}
				for _, s := range c.Subjects {
					cand.Candidate.Paths = append(cand.Candidate.Paths, s.Path)
					cand.Candidate.Symbols = append(cand.Candidate.Symbols, s.Symbol)
				}
				if gerr := groundClosingContract(&c, cand, sources, cfg.RepoRoot); gerr != nil {
					problem(c.InvariantID, gerr)
					continue
				}
				var postGroundSource []artifacts.ContractEvidenceRef
				for _, ref := range c.EvidenceRefs {
					if ref.Kind == "observation" {
						observationRefs = appendUniqueEvidenceRef(observationRefs, ref)
					} else {
						postGroundSource = append(postGroundSource, ref)
					}
				}
				sourceRefs = postGroundSource
			}
			c.EvidenceRefs = append(sourceRefs, toolFactRefs...)
		} else if observed != nil {
			var nonObs []artifacts.ContractEvidenceRef
			for _, ref := range c.EvidenceRefs {
				if ref.Kind == "observation" && observed.Observed(ref.Ref) {
					observationRefs = appendUniqueEvidenceRef(observationRefs, ref)
				} else {
					nonObs = append(nonObs, ref)
				}
			}
			c.EvidenceRefs = nonObs
		}

		bound, diagnostics, err := contracts.Bind(c, binding)
		if err != nil {
			problem(c.InvariantID, err)
			continue
		}
		for _, d := range diagnostics {
			problem(bound.InvariantID, fmt.Errorf("%s: %s", d.Code, d.Message))
		}
		if cfg.StrictContractExit && (bound.Grounding != "source_bound" || len(diagnostics) > 0) {
			if len(diagnostics) == 0 {
				problem(bound.InvariantID, fmt.Errorf("contract subjects could not be uniquely bound"))
			}
			continue
		}
		if err := contracts.ValidateVerificationQueries(bound); err != nil {
			problem(bound.InvariantID, err)
			continue
		}
		if err := contracts.Validate(bound, binding); err != nil {
			problem(bound.InvariantID, err)
			continue
		}
		for _, obsRef := range observationRefs {
			bound.EvidenceRefs = appendUniqueEvidenceRef(bound.EvidenceRefs, obsRef)
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
		if bound.Grounding == "source_bound" && len(diagnostics) == 0 && lead.State != artifacts.LeadStateClosed {
			updated := cloneLead(lead)
			updated.State = artifacts.LeadStateFormalized
			updated.ContractIDs = unionStrings(updated.ContractIDs, []string{bound.InvariantID})
			if updated.State != lead.State || len(updated.ContractIDs) != len(lead.ContractIDs) {
				if cfg.RunDir != "" {
					if err := appendAuditLead(runfs.AuditLeadsPath(cfg.RunDir), updated); err != nil {
						problem(bound.InvariantID, fmt.Errorf("persist formalized lead: %w", err))
						continue
					}
				}
				leadsByID[bound.LeadRef] = updated
				if state != nil {
					if idx, exists := leadIndexInState[bound.LeadRef]; exists {
						state.AuditLeads[idx] = updated
					}
				}
			}
		}
		if state != nil && bound.Grounding == "source_bound" && len(diagnostics) == 0 {
			state.Contracts = contracts.MergeAll(state.Contracts, []artifacts.CaseInvariantV2{bound})
			acceptedByHash[bound.DefinitionHash] = bound
		}
		out = append(out, bound)
	}
	return contracts.MergeAll(nil, out), problems
}

func cloneContractsSlice(in []artifacts.CaseInvariantV2) []artifacts.CaseInvariantV2 {
	if len(in) == 0 {
		return nil
	}
	return contracts.MergeAll(nil, in)
}

// partitionAcceptedContracts routes already-accepted contracts in state.Contracts
// either to the unique candidate they target (so they attach to that candidate's
// pack without creating a duplicate contract: pack) or to standalone invariants,
// WITHOUT re-running draft validation on them.
func partitionAcceptedContracts(
	accepted []artifacts.CaseInvariantV2,
	candidates []artifacts.Candidate,
) (map[int][]artifacts.CaseInvariantV2, []artifacts.CaseInvariantV2) {
	byCandidate := map[int][]artifacts.CaseInvariantV2{}
	var standalone []artifacts.CaseInvariantV2
	for _, c := range accepted {
		if c.Grounding != "source_bound" {
			continue
		}
		owner := -1
		for i, cand := range candidates {
			if contractTargetsCandidate(c, cand) {
				if owner != -1 {
					owner = -2
					break
				}
				owner = i
			}
		}
		if owner >= 0 {
			byCandidate[owner] = contracts.MergeAll(byCandidate[owner], []artifacts.CaseInvariantV2{c})
		} else {
			standalone = contracts.MergeAll(standalone, []artifacts.CaseInvariantV2{c})
		}
	}
	return byCandidate, standalone
}

func filterOutAcceptedDrafts(drafts []artifacts.CaseInvariantV2, accepted []artifacts.CaseInvariantV2) []artifacts.CaseInvariantV2 {
	if len(drafts) == 0 || len(accepted) == 0 {
		return drafts
	}
	known := make(map[string]bool, len(accepted))
	for _, c := range accepted {
		if c.Grounding == "source_bound" {
			known[contracts.DefinitionHash(c)] = true
		}
	}
	var out []artifacts.CaseInvariantV2
	for _, d := range drafts {
		if !known[contracts.DefinitionHash(d)] {
			out = append(out, d)
		}
	}
	return out
}

func leadBackedByAcceptedContract(lead artifacts.AuditLead, accepted []artifacts.CaseInvariantV2) bool {
	if len(accepted) == 0 {
		return false
	}
	byID := make(map[string]bool, len(accepted))
	for _, c := range accepted {
		if c.Grounding != "source_bound" {
			continue
		}
		if c.LeadRef != "" && c.LeadRef == lead.LeadID {
			return true
		}
		if c.InvariantID != "" {
			byID[c.InvariantID] = true
		}
	}
	for _, id := range lead.ContractIDs {
		if byID[id] {
			return true
		}
	}
	return false
}

func candidateCoveredByAcceptedContract(candidate artifacts.Candidate, accepted []artifacts.CaseInvariantV2) bool {
	for _, c := range accepted {
		if c.Grounding == "source_bound" && contractTargetsCandidate(c, candidate) {
			return true
		}
	}
	return false
}

func appendUniqueEvidenceRef(dst []artifacts.ContractEvidenceRef, item artifacts.ContractEvidenceRef) []artifacts.ContractEvidenceRef {
	rawItem, _ := json.Marshal(item)
	for _, existing := range dst {
		rawExisting, _ := json.Marshal(existing)
		if string(rawExisting) == string(rawItem) {
			return dst
		}
	}
	return append(dst, item)
}

func bindInvestigationContracts(
	rawInvestigations []map[string]any,
	cfg RunConfig,
	state *PlannerState,
	observed *ObservationSet,
	executedToolFactRefs []string,
	currentRound *artifacts.RoundRecord,
) []artifacts.RoundError {
	var errs []artifacts.RoundError
	roundNo := -1
	if currentRound != nil && currentRound.Round > 0 {
		roundNo = currentRound.Round
	}
	for i, m := range rawInvestigations {
		rawField, ok := m["case_invariants"]
		if !ok || rawField == nil {
			continue
		}
		encoded, err := json.Marshal(rawField)
		if err != nil {
			errs = append(errs, artifacts.RoundError{Round: roundNo, Action: fmt.Sprintf("done.investigations[%d].case_invariants", i), Error: err.Error()})
			m["case_invariants"] = []artifacts.CaseInvariantV2{}
			continue
		}
		var list []artifacts.CaseInvariantV2
		if err := json.Unmarshal(encoded, &list); err != nil {
			errs = append(errs, artifacts.RoundError{Round: roundNo, Action: fmt.Sprintf("done.investigations[%d].case_invariants", i), Error: err.Error()})
			m["case_invariants"] = []artifacts.CaseInvariantV2{}
			continue
		}
		if len(list) == 0 {
			continue
		}
		bound, bindErrs := bindPlannerContractsWithState(list, cfg, state, observed, executedToolFactRefs, currentRound)
		errs = append(errs, bindErrs...)
		m["case_invariants"] = bound
	}
	return errs
}

// acceptedContractCopies returns machine-owned contracts, never the model's
// anchors or claimed grounding. Final investigation assembly cannot accept new
// drafts or write additional lead revisions after the loop has stopped.
func acceptedContractCopies(drafts, accepted []artifacts.CaseInvariantV2) ([]artifacts.CaseInvariantV2, int) {
	byHash := make(map[string]artifacts.CaseInvariantV2, len(accepted))
	for _, c := range accepted {
		if c.Grounding == "source_bound" && c.DefinitionHash != "" && c.DefinitionHash == contracts.DefinitionHash(c) {
			byHash[c.DefinitionHash] = c
		}
	}
	var out []artifacts.CaseInvariantV2
	rejected := 0
	for _, draft := range drafts {
		if c, ok := byHash[contracts.DefinitionHash(draft)]; ok {
			out = append(out, c)
		} else {
			rejected++
		}
	}
	return cloneContractsSlice(out), rejected
}

func includeLeadTaintRefs(refs []artifacts.ContractEvidenceRef, lead artifacts.AuditLead) []artifacts.ContractEvidenceRef {
	out := append([]artifacts.ContractEvidenceRef(nil), refs...)
	for _, path := range lead.TaintFactRefs {
		found := false
		for _, ref := range out {
			if ref.Kind == "tool_fact" && ref.Ref == path {
				found = true
				break
			}
		}
		if !found {
			out = append(out, artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path})
		}
	}
	return out
}

func plannerBoundContractPacks(bound []artifacts.CaseInvariantV2, cfg RunConfig) []artifacts.CasePack {
	var packs []artifacts.CasePack
	for _, c := range bound {
		if cfg.StrictContractExit && c.Grounding != "source_bound" {
			continue
		}
		p := artifacts.CasePack{
			SchemaVersion:    "teecheck.case_pack.v1",
			CaseID:           "contract:" + c.InvariantID,
			Focus:            cfg.Profile.Focus,
			Priority:         "medium",
			Category:         "boundary",
			ContractRequired: true,
			CaseInvariants:   []artifacts.CaseInvariantV2{c},
			RelatedTWEs:      c.RelatedTWEs,
			WhySelected:      []string{c.RequiredProperty.Statement},
		}
		for _, s := range c.Subjects {
			p.TargetFiles = unionStrings(p.TargetFiles, []string{s.Path})
			p.TargetSymbols = unionStrings(p.TargetSymbols, []string{s.Symbol})
		}
		if c.Grounding != "source_bound" {
			p.CoverageGaps = append(p.CoverageGaps, "Contract subjects could not be uniquely bound.")
		}
		packs = append(packs, p)
	}
	return packs
}

func plannerContractPacks(raw []artifacts.CaseInvariantV2, cfg RunConfig) ([]artifacts.CasePack, []artifacts.RoundError) {
	bound, errs := bindPlannerContracts(raw, cfg)
	return plannerBoundContractPacks(bound, cfg), errs
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
