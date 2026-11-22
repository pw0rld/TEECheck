package planner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

const ActionFormalizeContract = "formalize_contract"

// formalizeContract validates while the planner can still correct the draft.
// It defines an obligation; none of these checks determines its truth.
func formalizeContract(cfg RunConfig, state *PlannerState, observed ObservationSet, executed []string, currentRound artifacts.RoundRecord, args json.RawMessage) actions.ActionResult {
	var payload struct {
		LeadID   string                    `json:"lead_id"`
		Contract artifacts.CaseInvariantV2 `json:"contract"`
	}
	fail := func(err error) actions.ActionResult { return leadActionFailure(ActionFormalizeContract, err) }
	if err := json.Unmarshal(args, &payload); err != nil {
		return fail(err)
	}
	index, err := currentLeadIndex(cfg, state, payload.LeadID)
	if err != nil {
		return fail(err)
	}
	c := payload.Contract
	if c.LeadRef != "" && c.LeadRef != payload.LeadID {
		return fail(fmt.Errorf("contract lead_ref differs from lead_id"))
	}
	c.LeadRef, c.Origin = payload.LeadID, "planner"
	c.EvidenceRefs = includeLeadTaintRefs(c.EvidenceRefs, state.AuditLeads[index])
	c.InvariantID = "case-inv-" + contracts.DefinitionHash(c)

	// ToolFact references must have been returned by a successful tool action
	// in this sample, not merely found in a previous pass's output directory.
	var extraRefs []artifacts.ContractEvidenceRef
	var sourceRefs []artifacts.ContractEvidenceRef
	for _, ref := range c.EvidenceRefs {
		if ref.Kind == "observation" {
			if !strings.HasPrefix(ref.Ref, "obs:") {
				return fail(fmt.Errorf("ToolFact paths and IDs must use evidence kind tool_fact, not observation"))
			}
			if !observed.Observed(ref.Ref) {
				return fail(fmt.Errorf("reference %q is not a successful observation in this sample", ref.Ref))
			}
			extraRefs = append(extraRefs, artifacts.ContractEvidenceRef{Kind: "observation", Ref: ref.Ref})
			continue
		}
		if ref.Kind != "tool_fact" {
			sourceRefs = append(sourceRefs, ref)
			continue
		}
		fact, path, err := resolveLeadFactRef(cfg, observed, executed, ref.Ref)
		if err != nil {
			return fail(err)
		}
		if fact == nil {
			return fail(fmt.Errorf("tool_fact reference must name an executed ToolFact"))
		}
		resolved := ref
		resolved.Ref = path
		extraRefs = append(extraRefs, resolved)
	}
	c.EvidenceRefs = sourceRefs
	snapshot := *state
	snapshot.Rounds = append(append([]artifacts.RoundRecord(nil), state.Rounds...), currentRound)
	candidate := formalizationCandidate{Leads: []artifacts.AuditLead{state.AuditLeads[index]}}
	for _, s := range c.Subjects {
		candidate.Candidate.Paths = append(candidate.Candidate.Paths, s.Path)
		candidate.Candidate.Symbols = append(candidate.Candidate.Symbols, s.Symbol)
	}
	if err := groundClosingContract(&c, candidate, observedSourceWindows(&snapshot, observed, observationlimits.MaxBytes), cfg.RepoRoot); err != nil {
		return fail(err)
	}
	c.EvidenceRefs = append(c.EvidenceRefs, extraRefs...)

	m, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fail(err)
	}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: cfg.RepoRoot, Scope: m.Scope}
	if binding.Scope.Commit == "" {
		binding.Scope = runfs.BuildScope(m.RepoURL, m.Commit, cfg.RepoRoot)
	}
	// Current-round observations are not in rounds.jsonl until the round
	// finishes. They were checked against the live sample above; the generic
	// binder handles source and ToolFact anchors separately, then we restore
	// the validated observation references to the persisted contract.
	var observationRefs []artifacts.ContractEvidenceRef
	evidence := c.EvidenceRefs
	c.EvidenceRefs = nil
	for _, ref := range evidence {
		if ref.Kind == "observation" {
			observationRefs = append(observationRefs, ref)
		} else {
			c.EvidenceRefs = append(c.EvidenceRefs, ref)
		}
	}
	bound, diagnostics, err := contracts.Bind(c, binding)
	if err != nil {
		return fail(err)
	}
	if bound.Grounding != "source_bound" || len(diagnostics) != 0 {
		return fail(fmt.Errorf("contract subjects could not be uniquely bound: %v", diagnostics))
	}
	if err := contracts.ValidateVerificationQueries(bound); err != nil {
		return fail(err)
	}
	if err := contracts.Validate(bound, binding); err != nil {
		return fail(err)
	}
	bound.EvidenceRefs = append(bound.EvidenceRefs, observationRefs...)
	path := filepath.Join(runfs.PlannerDir(cfg.RunDir), "contracts", bound.DefinitionHash+".json")
	if err := runfs.WriteJSON(path, bound); err != nil {
		return fail(err)
	}
	lead := cloneLead(state.AuditLeads[index])
	lead.State = artifacts.LeadStateFormalized
	lead.ContractIDs = unionStrings(lead.ContractIDs, []string{bound.InvariantID})
	if err := saveLeadRevision(cfg, state, index, lead); err != nil {
		return fail(err)
	}
	state.Contracts = contracts.MergeAll(state.Contracts, []artifacts.CaseInvariantV2{bound})
	body, _ := json.Marshal(map[string]any{"lead_id": lead.LeadID, "state": lead.State, "contract_id": bound.InvariantID, "contract": bound})
	return actions.ActionResult{Name: ActionFormalizeContract, OK: true, Output: string(body)}
}
