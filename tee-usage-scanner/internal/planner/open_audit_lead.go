package planner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// OpenAuditLeadPayload is what the model sends to raise a lead.
type OpenAuditLeadPayload struct {
	SecurityQuestion string               `json:"security_question"`
	TargetSymbolIDs  []artifacts.SymbolID `json:"target_symbol_ids"`
	Reason           []string             `json:"reason"`
	ReasonFactRefs   []string             `json:"reason_fact_refs"`
	RequestedContext []string             `json:"requested_context"`
	Uncertainty      string               `json:"uncertainty"`
	RelatedTWEs      []string             `json:"related_twes"`
}

// validUncertainty is the Planner's own confidence that the question is
// worth answering. It is not a severity, and it is a closed set so that a
// value nobody defined cannot arrive downstream reading like one.
var validUncertainty = map[string]bool{"low": true, "medium": true, "high": true}

// tryOpenAuditLead is dispatched by the planner loop, not by the registry.
//
// It needs the live ReconState and the pass's observation set, to check that
// the lead's symbols and reasons were actually seen in this pass. An
// actions.Handler receives only an ActionRequest, so a registry handler
// would have to re-read artifacts from disk and guess what the planner saw —
// which is exactly the kind of "reconstruct the context" step that produces
// a citation to something nobody looked at.
//
// It returns the lead with its content fields filled and State open; the
// caller stamps the identity (lead id, run, sample, round) and persists,
// because those are facts about the loop rather than about the payload.
//
// Every failure is reported at once rather than one per round. A model that
// learns its payload was malformed only after the gate lifts has spent a
// round to discover the second problem.
func tryOpenAuditLead(
	recon *ReconState,
	observations ObservationSet,
	payload OpenAuditLeadPayload,
) (artifacts.AuditLead, actions.ActionResult) {
	return tryOpenAuditLeadWithPrescan(recon, observations, payload, false)
}

func tryOpenAuditLeadWithPrescan(recon *ReconState, observations ObservationSet, payload OpenAuditLeadPayload, targetedSourceRead bool) (artifacts.AuditLead, actions.ActionResult) {
	var problems []string

	if !recon.AllowLead() && !targetedSourceRead {
		problems = append(problems,
			"reconnaissance is not complete, so there is not yet enough of this project "+
				"in view to say which question matters. Still needed:\n"+recon.Unmet())
	}

	if strings.TrimSpace(payload.SecurityQuestion) == "" {
		problems = append(problems, "security_question is empty — a lead is a question, and an unstated one cannot be investigated or closed")
	}

	if len(payload.TargetSymbolIDs) == 0 {
		problems = append(problems,
			"target_symbol_ids is empty — name the definitions by the symbol_id "+
				"find_symbols or list_functions gave you. A function name is not an identity: "+
				"two files can each define a static function of the same name")
	}
	var unseen []string
	for _, id := range payload.TargetSymbolIDs {
		if !recon.SawSymbol(id) && !targetedSourceRead {
			unseen = append(unseen, string(id))
		}
	}
	if len(unseen) > 0 {
		problems = append(problems, fmt.Sprintf(
			"these targets were never opened in this pass: %s. Call get_function_card "+
				"on each before making it the subject of a question",
			strings.Join(unseen, ", ")))
	}

	if len(payload.Reason) == 0 {
		problems = append(problems, "reason is empty — say what about the code raised the question")
	}
	if len(payload.ReasonFactRefs) == 0 {
		problems = append(problems,
			"reason_fact_refs is empty — each reason must cite the observation that showed it, "+
				"by the ref printed beside that observation (ref=obs:...). A reason with no ref "+
				"is not a weaker citation, it is not a citation")
	}
	var ungrounded []string
	resolvedRefs := make([]string, 0, len(payload.ReasonFactRefs))
	for _, ref := range payload.ReasonFactRefs {
		if full, ok := observations.Resolve(ref); ok {
			resolvedRefs = append(resolvedRefs, full)
		} else {
			ungrounded = append(ungrounded, ref)
		}
	}
	if len(ungrounded) == 0 && len(resolvedRefs) > 0 {
		payload.ReasonFactRefs = resolvedRefs
	}
	if len(ungrounded) > 0 {
		problems = append(problems, fmt.Sprintf(
			"these refs name no successful observation in this pass: %s. "+
				"Cite only refs printed beside an observation marked OK",
			strings.Join(ungrounded, ", ")))
	}

	if payload.Uncertainty != "" && !validUncertainty[payload.Uncertainty] {
		problems = append(problems, fmt.Sprintf(
			"uncertainty %q is not one of low, medium, high", payload.Uncertainty))
	}

	if len(problems) > 0 {
		return artifacts.AuditLead{}, actions.ActionResult{
			Name:  ActionOpenAuditLead,
			OK:    false,
			Error: "open_audit_lead refused:\n  - " + strings.Join(problems, "\n  - "),
		}
	}

	lead := artifacts.AuditLead{
		SchemaVersion:    "teecheck.audit_lead.v1",
		TargetSymbolIDs:  payload.TargetSymbolIDs,
		SecurityQuestion: payload.SecurityQuestion,
		Reason:           payload.Reason,
		ReasonFactRefs:   payload.ReasonFactRefs,
		RequestedContext: payload.RequestedContext,
		Uncertainty:      payload.Uncertainty,
		// §6.4: related_twes may be empty, and must be allowed to be. A
		// question describing a break this project has that no playbook
		// names is not a lesser question.
		RelatedTWEs: payload.RelatedTWEs,
		State:       artifacts.LeadStateOpen,
	}
	recon.OpenedLead()

	return lead, actions.ActionResult{
		Name:   ActionOpenAuditLead,
		OK:     true,
		Output: leadAcceptedMessage(lead),
	}
}

// ActionOpenAuditLead is the name the model calls. It is a control action in
// the planner core rather than a registry handler, but the model's interface
// is unchanged: it appears in the prompt's action list like any other.
const ActionOpenAuditLead = "open_audit_lead"

func leadAcceptedMessage(lead artifacts.AuditLead) string {
	var b strings.Builder
	b.WriteString("lead opened; you are now investigating it.\n")
	fmt.Fprintf(&b, "question: %s\n", lead.SecurityQuestion)
	fmt.Fprintf(&b, "targets: %s\n", joinIDs(lead.TargetSymbolIDs))
	b.WriteString("Expand it: read the bodies, follow the callers, and check whether the " +
		"contract you suspect is broken actually is. Closing it with evidence that it holds " +
		"is as complete an answer as finding that it does not.\n")
	return b.String()
}

func joinIDs(ids []artifacts.SymbolID) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return strings.Join(out, ", ")
}

// parseOpenAuditLead decodes the model's args. A malformed payload is
// refused with the parse error rather than treated as an empty lead — an
// empty lead would then fail the content checks and report the wrong cause.
func parseOpenAuditLead(args json.RawMessage) (OpenAuditLeadPayload, error) {
	var p OpenAuditLeadPayload
	if len(args) == 0 {
		return p, fmt.Errorf("no args")
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return p, err
	}
	return p, nil
}
