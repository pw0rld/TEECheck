package planner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

const (
	ActionUpdateLead = "update_lead"
	ActionCloseLead  = "close_lead"
	maxLeadNoteBytes = 240
	maxLeadNotes     = 32
	maxLeadRefs      = 32
)

type updateLeadPayload struct {
	LeadID   string `json:"lead_id"`
	AddNotes []struct {
		FactRef string `json:"fact_ref"`
		Summary string `json:"summary"`
	} `json:"add_notes"`
	AddTaintFactRefs []string `json:"add_taint_fact_refs"`
	AddRuledOut      []string `json:"add_ruled_out"`
}

type closeLeadPayload struct {
	LeadID   string   `json:"lead_id"`
	Reason   string   `json:"reason"`
	FactRefs []string `json:"fact_refs"`
}

func updateLead(cfg RunConfig, state *PlannerState, observed ObservationSet, executedToolFactRefs []string, args json.RawMessage, round int) actions.ActionResult {
	var payload updateLeadPayload
	if err := json.Unmarshal(args, &payload); err != nil {
		return leadActionFailure(ActionUpdateLead, err)
	}
	index, err := currentLeadIndex(cfg, state, payload.LeadID)
	if err != nil {
		return leadActionFailure(ActionUpdateLead, err)
	}
	if len(payload.AddNotes)+len(payload.AddTaintFactRefs)+len(payload.AddRuledOut) == 0 {
		return leadActionFailure(ActionUpdateLead, fmt.Errorf("provide at least one evidence note, taint fact, or ruled-out hypothesis"))
	}
	lead := cloneLead(state.AuditLeads[index])
	for _, ref := range payload.AddTaintFactRefs {
		fact, path, err := resolveLeadFactRef(cfg, observed, executedToolFactRefs, ref)
		if err != nil {
			return leadActionFailure(ActionUpdateLead, err)
		}
		if fact == nil || !artifacts.IsTaintOperation(fact.Operation) {
			return leadActionFailure(ActionUpdateLead, fmt.Errorf("taint reference must name a successful cpp.taint.trace or cpp.taint.prescan ToolFact observed in this sample"))
		}
		lead.TaintFactRefs = unionStrings(lead.TaintFactRefs, []string{path})
	}
	for _, note := range payload.AddNotes {
		note.Summary = strings.TrimSpace(note.Summary)
		if note.Summary == "" || len(note.Summary) > maxLeadNoteBytes || !utf8.ValidString(note.Summary) {
			return leadActionFailure(ActionUpdateLead, fmt.Errorf("note summary must contain 1–240 UTF-8 bytes"))
		}
		_, canonicalRef, err := resolveLeadFactRef(cfg, observed, executedToolFactRefs, note.FactRef)
		if err != nil {
			return leadActionFailure(ActionUpdateLead, err)
		}
		note.FactRef = canonicalRef
		duplicate := false
		for _, old := range lead.EvidenceNotes {
			if old.FactRef == note.FactRef && old.Summary == note.Summary {
				duplicate = true
				break
			}
		}
		if !duplicate {
			lead.EvidenceNotes = append(lead.EvidenceNotes, artifacts.LeadEvidenceNote{FactRef: note.FactRef, Summary: note.Summary, AddedAtRound: round})
		}
	}
	if len(payload.AddRuledOut) > 0 && len(lead.EvidenceNotes) == 0 {
		return leadActionFailure(ActionUpdateLead, fmt.Errorf("ruled-out hypotheses require an evidence note with a validated reference"))
	}
	for _, hypothesis := range payload.AddRuledOut {
		hypothesis = strings.TrimSpace(hypothesis)
		if hypothesis == "" || len(hypothesis) > maxLeadNoteBytes || !utf8.ValidString(hypothesis) {
			return leadActionFailure(ActionUpdateLead, fmt.Errorf("ruled-out hypothesis must contain 1–240 UTF-8 bytes"))
		}
		lead.RuledOut = unionStrings(lead.RuledOut, []string{hypothesis})
	}
	if len(lead.EvidenceNotes) > maxLeadNotes || len(lead.TaintFactRefs) > maxLeadRefs || len(lead.RuledOut) > maxLeadNotes {
		return leadActionFailure(ActionUpdateLead, fmt.Errorf("lead evidence exceeds the 32-item limit; retain compact notes"))
	}
	if lead.State == artifacts.LeadStateOpen {
		lead.State = artifacts.LeadStateExpanded
	}
	if err := saveLeadRevision(cfg, state, index, lead); err != nil {
		return leadActionFailure(ActionUpdateLead, err)
	}
	return leadActionSuccess(ActionUpdateLead, lead)
}

func closeLead(cfg RunConfig, state *PlannerState, observed ObservationSet, executedToolFactRefs []string, args json.RawMessage, round int) actions.ActionResult {
	var payload closeLeadPayload
	if err := json.Unmarshal(args, &payload); err != nil {
		return leadActionFailure(ActionCloseLead, err)
	}
	index, err := currentLeadIndex(cfg, state, payload.LeadID)
	if err != nil {
		return leadActionFailure(ActionCloseLead, err)
	}
	payload.Reason = strings.TrimSpace(payload.Reason)
	if payload.Reason == "" || len(payload.Reason) > 1024 || !utf8.ValidString(payload.Reason) {
		return leadActionFailure(ActionCloseLead, fmt.Errorf("close reason must contain 1–1024 UTF-8 bytes"))
	}
	if len(payload.FactRefs) == 0 || len(payload.FactRefs) > maxLeadRefs {
		return leadActionFailure(ActionCloseLead, fmt.Errorf("closing requires 1–32 current-pass evidence references"))
	}
	resolvedCloseRefs := make([]string, 0, len(payload.FactRefs))
	for _, ref := range payload.FactRefs {
		_, canonicalRef, err := resolveLeadFactRef(cfg, observed, executedToolFactRefs, ref)
		if err != nil {
			return leadActionFailure(ActionCloseLead, err)
		}
		resolvedCloseRefs = append(resolvedCloseRefs, canonicalRef)
	}
	lead := cloneLead(state.AuditLeads[index])
	lead.State = artifacts.LeadStateClosed
	lead.CloseReason = payload.Reason
	lead.CloseFactRefs = unionStrings(nil, resolvedCloseRefs)
	if err := saveLeadRevision(cfg, state, index, lead); err != nil {
		return leadActionFailure(ActionCloseLead, err)
	}
	return leadActionSuccess(ActionCloseLead, lead)
}

// currentLeadIndex accepts only mutable leads belonging to this exact sample.
// Callers should use saveLeadRevision after validating the entire update, so a
// bad final reference or a persistence error cannot partially change memory.
func currentLeadIndex(cfg RunConfig, state *PlannerState, id string) (int, error) {
	if state == nil || strings.TrimSpace(id) == "" {
		return -1, fmt.Errorf("lead_id must name a current-sample open lead")
	}
	for i := range state.AuditLeads {
		lead := &state.AuditLeads[i]
		if lead.LeadID != id || lead.RunID != cfg.RunID || lead.SampleIndex != cfg.SampleIndex {
			continue
		}
		if lead.State == artifacts.LeadStateClosed {
			return -1, fmt.Errorf("lead %q is closed", id)
		}
		return i, nil
	}
	return -1, fmt.Errorf("lead %q does not belong to the current run and sample", id)
}

func saveLeadRevision(cfg RunConfig, state *PlannerState, index int, lead artifacts.AuditLead) error {
	if cfg.RunDir != "" {
		if err := appendAuditLead(runfs.AuditLeadsPath(cfg.RunDir), lead); err != nil {
			return fmt.Errorf("persist lead revision: %w", err)
		}
	}
	state.AuditLeads[index] = lead
	return nil
}

func validateLeadFactRef(cfg RunConfig, observed ObservationSet, executed []string, ref string) (*artifacts.ToolFact, error) {
	fact, _, err := resolveLeadFactRef(cfg, observed, executed, ref)
	return fact, err
}

func resolveLeadFactRef(cfg RunConfig, observed ObservationSet, executed []string, ref string) (*artifacts.ToolFact, string, error) {
	if strings.HasPrefix(ref, "obs:") {
		full, ok := observed.Resolve(ref)
		if !ok {
			return nil, "", fmt.Errorf("reference %q is not a unique successful observation in this sample", ref)
		}
		return nil, full, nil
	}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, Scope: artifacts.ScannedScope{Commit: cfg.Profile.Commit}}
	if manifest, err := runfs.LoadManifest(cfg.RunDir); err == nil {
		binding.Scope = manifest.Scope
		if binding.Scope.Commit == "" {
			binding.Scope.Commit = manifest.Commit
		}
	}
	for _, path := range executed {
		if _, err := contracts.ResolveEvidence(artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path}, binding); err != nil {
			continue
		}
		full := path
		if !filepath.IsAbs(full) {
			if absolute, err := filepath.Abs(full); err == nil {
				root, _ := filepath.Abs(cfg.RunDir)
				if rel, err := filepath.Rel(root, absolute); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					full = absolute
				} else {
					full = filepath.Join(root, full)
				}
			}
		}
		var fact artifacts.ToolFact
		if err := runfs.ReadJSON(full, &fact); err != nil || fact.Status != "success" {
			continue
		}
		if fact.Operation == artifacts.TaintPrescanOperation {
			context, verified, err := validatePreScannedTaint(cfg)
			if err != nil || context == nil || verified == nil || !observed.Observed(context.FactRef) || filepath.Clean(full) != prescanFactPath(cfg) || fact.ContentSHA256 != verified.ContentSHA256 {
				continue
			}
		}
		if ref == path || (fact.FactID != "" && ref == fact.FactID) {
			return &fact, full, nil
		}
	}
	return nil, "", fmt.Errorf("reference %q is not a successful ToolFact executed in this sample", ref)
}

func cloneLead(lead artifacts.AuditLead) artifacts.AuditLead {
	lead.EvidenceNotes = append([]artifacts.LeadEvidenceNote(nil), lead.EvidenceNotes...)
	lead.TaintFactRefs = append([]string(nil), lead.TaintFactRefs...)
	lead.RuledOut = append([]string(nil), lead.RuledOut...)
	lead.ContractIDs = append([]string(nil), lead.ContractIDs...)
	lead.CloseFactRefs = append([]string(nil), lead.CloseFactRefs...)
	return lead
}

func leadActionFailure(name string, err error) actions.ActionResult {
	return actions.ActionResult{Name: name, Error: name + ": " + err.Error()}
}

func leadActionSuccess(name string, lead artifacts.AuditLead) actions.ActionResult {
	body, _ := json.Marshal(lead)
	return actions.ActionResult{Name: name, OK: true, Output: string(body)}
}
