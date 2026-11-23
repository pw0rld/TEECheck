package planner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// passBOnlyActions apply TWE prior knowledge and are withheld until the
// Planner has a lead of its own. Structural tracing remains available in
// reconnaissance so it can supply evidence for opening that first lead.
//
// TWE detail requires an investigation lead. The fact_layer_query and
// trace_taint actions are not restricted: they answer a
// structural question the Planner chose to ask, which is what
// reconnaissance is for. The distinction is what the action primes, not
// whether it is expensive.
var passBOnlyActions = []string{"twe_playbook_detail"}

// advertisedActions is the registry's actions plus the control actions the
// planner core dispatches itself. From the model's side there is no
// difference — open_audit_lead appears in the list like any other.
func advertisedActions(reg *actions.Registry) []string {
	names := reg.Names()
	out := make([]string, 0, len(names)+1)
	out = append(out, names...)
	out = append(out, ActionOpenAuditLead)
	out = append(out, ActionUpdateLead, ActionFormalizeContract, ActionCloseLead)
	sort.Strings(out)
	return out
}

// loadProjectMap reads the run's project map and says whether there was one.
//
// The distinction matters. A map that reports an unindexable repository is
// the reconnaissance stage's answer, and the gate holds the Planner to it.
// No map at all means the stage never ran — the pipeline always writes one,
// so this is a caller driving planner.Run directly — and a gate derived from
// an artifact that does not exist would hold the Planner to nothing while
// costing it every round it has.
func loadProjectMap(runDir string) (artifacts.ProjectMap, bool) {
	var m artifacts.ProjectMap
	if runDir == "" {
		return m, false
	}
	if err := runfs.ReadJSON(runfs.ProjectMapPath(runDir), &m); err != nil {
		return artifacts.ProjectMap{}, false
	}
	return m, true
}

func totalFunctions(m artifacts.ProjectMap) int {
	n := 0
	for _, mod := range m.Modules {
		n += mod.FunctionCount
	}
	return n
}

// reconStatusBlock tells the model where it stands against the gate. A gate
// the model cannot see is one it can only hit.
//
// It is the last thing in the round prompt, so it ends by restating the
// response format. On the first real run against OP-TEE it did not, and the
// model — reading a checklist of things to do as the final instruction —
// replied with prose describing what it was about to do, twice in a row.
// The run died on round 6 with llm_malformed. A checklist is not an
// instruction to act; whatever sits last has to say how to answer.
func reconStatusBlock(r *ReconState) string {
	if r.Skipped() || r.Phase() == PhaseInvestigation {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n=== RECONNAISSANCE ===\n")
	fmt.Fprintf(&b, "mode: %s\n", r.Mode)

	unmet := r.Unmet()
	switch {
	case r.Status() == reconStatusBudgetExhausted:
		// Once the escape has fired, what is unmet is history, not a
		// precondition. Printing both — "you still need to" and "the gate
		// is no longer blocking" — told the model two opposite things in
		// consecutive sentences.
		b.WriteString("Your reconnaissance rounds are spent, so the gate is no longer blocking.\n")
		if unmet != "" {
			b.WriteString("You did not get to:\n" + unmet + "\n")
		}
		b.WriteString("Open a lead (open_audit_lead) on the strongest question your reading did raise, " +
			"and say in its reason what you did not get to look at.\n")
	case unmet != "":
		b.WriteString("Before you can open a lead or call done, you still need to:\n" + unmet + "\n")
	default:
		b.WriteString("You have seen enough of this project. Open a lead (open_audit_lead) " +
			"on the question your reading actually raised.\n")
	}

	b.WriteString("\nReply with the JSON object described in the system prompt and nothing else — " +
		"no prose before it, no prose after it, no markdown fence.\n")
	if gaps := r.EntryCoverageGaps(); len(gaps) > 0 && r.LeadsOpened() == 0 {
		b.WriteString("\nBefore normal completion with zero leads, inspect entry source (do not invent a lead):\n  - " + strings.Join(gaps, "\n  - ") + "\n")
	}
	return b.String()
}

// openLead validates the model's payload, stamps the lead's identity and
// appends it to the run's leads.
//
// The identity is stamped here rather than in tryOpenAuditLead because it
// is a fact about the loop — which run, which sample, which round — and not
// about the payload. Keeping the validator free of it also keeps it free of
// the filesystem.
func openLead(
	cfg RunConfig,
	recon *ReconState,
	observations ObservationSet,
	args json.RawMessage,
	round int,
	states ...*PlannerState,
) (artifacts.AuditLead, actions.ActionResult) {
	payload, err := parseOpenAuditLead(args)
	if err != nil {
		return artifacts.AuditLead{}, actions.ActionResult{
			Name:  ActionOpenAuditLead,
			OK:    false,
			Error: "open_audit_lead: could not read the args: " + err.Error(),
		}
	}

	var state *PlannerState
	if len(states) > 0 {
		state = states[0]
	}
	targeted, err := prescanLeadSourceRead(cfg, recon, state, observations, payload)
	if err != nil {
		return artifacts.AuditLead{}, leadActionFailure(ActionOpenAuditLead, err)
	}
	lead, res := tryOpenAuditLeadWithPrescan(recon, observations, payload, targeted)
	if !res.OK {
		return lead, res
	}

	lead.RunID = cfg.RunID
	lead.SampleIndex = cfg.SampleIndex
	lead.OpenedAtRound = round
	lead.LeadID = fmt.Sprintf("lead-s%d-%03d", cfg.SampleIndex, recon.LeadsOpened())
	identity, _ := json.Marshal(map[string]string{"lead_id": lead.LeadID})
	res.Output += "\n" + string(identity)

	if cfg.RunDir != "" {
		if err := appendAuditLead(runfs.AuditLeadsPath(cfg.RunDir), lead); err != nil {
			// The lead is still open — the pass has flipped and the model
			// has been told so. Reporting the write failure as a refusal
			// would contradict a state change that already happened.
			res.Output += fmt.Sprintf("\n(warning: this lead was not persisted: %v)", err)
		}
	}
	return lead, res
}

func appendAuditLead(path string, lead artifacts.AuditLead) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	line, err := json.Marshal(lead)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// writeCoverageLedger records what this pass looked at and, more
// importantly, what nobody did (§6.5).
//
// One ledger per run: it is read, this sample's entry replaced, and the
// unions recomputed. A file per sample would make every downstream consumer
// re-aggregate, and the totals are unions rather than sums — two passes
// that opened the same module reviewed one module, not two.
func writeCoverageLedger(cfg RunConfig, recon *ReconState, m artifacts.ProjectMap, leadsOpen int, states ...*PlannerState) error {
	if cfg.RunDir == "" {
		return nil
	}
	path := runfs.CoverageLedgerPath(cfg.RunDir)

	var ledger artifacts.CoverageLedger
	_ = runfs.ReadJSON(path, &ledger)

	ledger.SchemaVersion = "teecheck.coverage_ledger.v1"
	ledger.RunID = cfg.RunID
	ledger.ModulesTotal = len(m.Modules)
	ledger.FunctionCapsulesTotal = totalFunctions(m)

	reconStatus := recon.Status()
	if cfg.StrictContractExit && len(states) > 0 && states[0] != nil && len(unresolvedSampleLeads(states[0], cfg.RunID, cfg.SampleIndex)) > 0 {
		reconStatus = reconStatusIncomplete
	}
	entry := artifacts.SampleCoverage{
		SampleIndex:        cfg.SampleIndex,
		ReconMode:          string(recon.Mode),
		ReconStatus:        reconStatus,
		ModulesReviewed:    recon.ModulesReviewed(),
		CapsulesReviewed:   recon.DistinctSymbolsViewed(),
		FilesRead:          recon.DistinctFilesRead(),
		RelationQueriesRun: recon.RelationQueries(),
		RoundsUsed:         cfg.Budget.RoundsUsed,
		ReconRoundsUsed:    cfg.Budget.ReconRoundsUsed,
		LeadsOpened:        leadsOpen,
	}
	entryCoverage := recon.EntryCoverage()
	entry.EntrySurfaces = &artifacts.EntrySurfaceCoverage{
		Capability: entryCoverage.Capability, Total: entryCoverage.Total,
		Required: entryCoverage.Required, Read: entryCoverage.Read,
		ModulesTotal: entryCoverage.ModulesTotal, ModulesRequired: entryCoverage.ModulesRequired, ModulesRead: entryCoverage.ModulesRead,
		ReadSymbolIDs: entryCoverage.ReadSymbolIDs, GateApplies: entryCoverage.GateApplies,
		Complete: len(recon.EntryCoverageGaps()) == 0, CoverageGaps: recon.EntryCoverageGaps(),
	}
	if current, err := contractLeads(cfg); err == nil {
		for _, lead := range current {
			if lead.State == artifacts.LeadStateClosed {
				entry.LeadsClosed++
			}
		}
	}
	replaced := false
	for i := range ledger.BySample {
		if ledger.BySample[i].SampleIndex == entry.SampleIndex {
			ledger.BySample[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		ledger.BySample = append(ledger.BySample, entry)
	}
	sort.Slice(ledger.BySample, func(i, j int) bool {
		return ledger.BySample[i].SampleIndex < ledger.BySample[j].SampleIndex
	})

	reviewed := map[string]bool{}
	capsules, leads := 0, 0
	for _, s := range ledger.BySample {
		for _, mod := range s.ModulesReviewed {
			reviewed[mod] = true
		}
		capsules += s.CapsulesReviewed
		leads += max(0, s.LeadsOpened-s.LeadsClosed)
	}
	ledger.ModulesReviewed = len(reviewed)
	ledger.FunctionCapsulesReviewed = capsules
	ledger.LeadsOpen = leads

	// Written even when it is long. An omitted list reads as "nothing was
	// missed", which is the opposite of what a long one means — §6.5 is
	// explicit that an unreviewed cluster is a coverage gap and never an
	// absence of risk.
	ledger.UnreviewedClusters = []string{}
	for _, mod := range m.Modules {
		if !reviewed[mod.Path] {
			ledger.UnreviewedClusters = append(ledger.UnreviewedClusters, mod.Path)
		}
	}
	sort.Strings(ledger.UnreviewedClusters)

	return runfs.WriteJSON(path, ledger)
}
