package planner

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// Notes are sticky working memory, unlike the two-round tool-output window.
// Bound whole JSON records and report omitted items rather than slicing JSON
// or allowing one lead's history to crowd out the next investigation.
func leadMemoryBlock(state *PlannerState, limit int) string {
	if len(state.AuditLeads) == 0 || limit < 512 {
		return ""
	}
	var b strings.Builder
	b.WriteString("=== ACTIVE AUDIT LEADS (notes are cited hypotheses, not verified findings) ===\n")
	closed := []artifacts.AuditLead{}
	omitted := 0
	for i := len(state.AuditLeads) - 1; i >= 0; i-- {
		lead := state.AuditLeads[i]
		if lead.RunID != "" && lead.RunID != state.RunID {
			continue
		}
		if lead.State == artifacts.LeadStateClosed {
			closed = append(closed, lead)
			continue
		}
		line := compactLead(lead)
		if b.Len()+len(line)+256 > limit {
			omitted++
			continue
		}
		b.WriteString(line)
	}
	if omitted > 0 {
		fmt.Fprintf(&b, "(%d additional active leads omitted by prompt budget; full revisions remain in audit_leads.jsonl.)\n", omitted)
	}
	if len(closed) > 0 {
		b.WriteString("CLOSED LEADS (archived investigation decisions; not safety proofs):\n")
		shown := 0
		for _, lead := range closed {
			row, _ := json.Marshal(map[string]any{"lead_id": lead.LeadID, "state": lead.State, "reason": boundedMemoryText(lead.CloseReason, 160), "contract_ids": lead.ContractIDs})
			if b.Len()+len(row)+128 > limit {
				continue
			}
			b.Write(row)
			b.WriteByte('\n')
			shown++
		}
		if shown < len(closed) {
			fmt.Fprintf(&b, "(%d closed leads omitted by prompt budget.)\n", len(closed)-shown)
		}
	}
	return b.String()
}

func compactLead(lead artifacts.AuditLead) string {
	type memory struct {
		ID        string                       `json:"lead_id"`
		State     string                       `json:"state"`
		Question  string                       `json:"security_question"`
		Targets   []artifacts.SymbolID         `json:"targets"`
		Reasons   []string                     `json:"reason_fact_refs,omitempty"`
		Notes     []artifacts.LeadEvidenceNote `json:"evidence_notes,omitempty"`
		Taint     []string                     `json:"taint_fact_refs,omitempty"`
		RuledOut  []string                     `json:"ruled_out,omitempty"`
		Contracts []string                     `json:"contract_ids,omitempty"`
		Omitted   int                          `json:"omitted_items,omitempty"`
	}
	m := memory{lead.LeadID, boundedMemoryText(lead.State, 32), boundedMemoryText(lead.SecurityQuestion, 400), append([]artifacts.SymbolID(nil), lead.TargetSymbolIDs...), append([]string(nil), lead.ReasonFactRefs...), append([]artifacts.LeadEvidenceNote(nil), lead.EvidenceNotes...), append([]string(nil), lead.TaintFactRefs...), append([]string(nil), lead.RuledOut...), append([]string(nil), lead.ContractIDs...), 0}
	for {
		data, _ := json.Marshal(m)
		if len(data)+1 <= 2048 {
			return string(data) + "\n"
		}
		switch {
		case len(m.Notes) > 0:
			m.Notes = m.Notes[1:]
		case len(m.RuledOut) > 0:
			m.RuledOut = m.RuledOut[1:]
		case len(m.Reasons) > 0:
			m.Reasons = m.Reasons[:len(m.Reasons)-1]
		case len(m.Taint) > 0:
			m.Taint = m.Taint[:len(m.Taint)-1]
		case len(m.Contracts) > 0:
			m.Contracts = m.Contracts[:len(m.Contracts)-1]
		case len(m.Targets) > 0:
			m.Targets = m.Targets[:len(m.Targets)-1]
		default:
			m.ID = boundedMemoryText(m.ID, 128)
			m.Question = boundedMemoryText(m.Question, 128)
		}
		m.Omitted++
	}
}

func boundedMemoryText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
