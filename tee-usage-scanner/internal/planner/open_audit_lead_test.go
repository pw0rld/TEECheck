package planner

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// openedRecon returns a pass that has finished reconnaissance and opened the
// card for target, with one grounded observation.
func openedRecon(t *testing.T, target artifacts.SymbolID) (*ReconState, ObservationSet, string) {
	t.Helper()
	r := NewReconState(ReconModeIndexed)
	browse(r)
	r.Observe("get_function_card", string(target), true)
	if !r.AllowLead() {
		t.Fatalf("baseline gate must be open:\n%s", r.Unmet())
	}

	ref := MakeObservationRef("run-1", 0, 4, 0, "sha256:aaa")
	var obs ObservationSet
	obs.Record(ref, true)
	return r, obs, ref
}

const targetID = artifacts.SymbolID("cpp:core/crypto/signed_hdr.c:262:shdr_load_pub_key(struct shdr * shdr)")

func goodPayload(ref string) OpenAuditLeadPayload {
	return OpenAuditLeadPayload{
		SecurityQuestion: "does subkey_version reach pub_key.version?",
		TargetSymbolIDs:  []artifacts.SymbolID{targetID},
		Reason:           []string{"producer does not write key.version"},
		ReasonFactRefs:   []string{ref},
		Uncertainty:      "high",
	}
}

// A lead whose reasons cite nothing the planner looked at is a guess with a
// citation-shaped field. That is exactly the failure: an invariant anchored
// on a line nobody had read.
func TestOpenAuditLead_RejectsReasonsWithNoObservedFact(t *testing.T) {
	recon, _, _ := openedRecon(t, targetID)

	p := goodPayload("")
	p.ReasonFactRefs = nil
	_, res := tryOpenAuditLead(recon, ObservationSet{}, p)
	if res.OK {
		t.Fatal("a lead with no fact refs must be refused")
	}
	if !strings.Contains(res.Error, "reason_fact_refs") {
		t.Errorf("the refusal must name what is missing: %s", res.Error)
	}
}

// A ref that resolves to nothing is worse than no ref: it looks checked.
func TestOpenAuditLead_RejectsRefsThatNameNoObservation(t *testing.T) {
	recon, obs, _ := openedRecon(t, targetID)

	p := goodPayload("obs:0:9:9:notarealref")
	_, res := tryOpenAuditLead(recon, obs, p)
	if res.OK {
		t.Fatal("an invented ref must be refused")
	}
	if !strings.Contains(res.Error, "obs:0:9:9:notarealref") {
		t.Errorf("the refusal must name the ref that did not resolve: %s", res.Error)
	}
}

// An action that failed observed nothing, so its ref grounds nothing —
// otherwise seven consecutive ripgrep failures would each be citable.
func TestOpenAuditLead_AFailedObservationDoesNotGround(t *testing.T) {
	recon, _, _ := openedRecon(t, targetID)

	ref := MakeObservationRef("run-1", 0, 4, 1, "sha256:bbb")
	var obs ObservationSet
	obs.Record(ref, false)

	_, res := tryOpenAuditLead(recon, obs, goodPayload(ref))
	if res.OK {
		t.Fatal("a ref pointing at a failed action must be refused")
	}
}

// A lead about a function nobody opened is a guess about a name.
func TestOpenAuditLead_RejectsUnobservedSymbols(t *testing.T) {
	recon, obs, ref := openedRecon(t, targetID)

	p := goodPayload(ref)
	p.TargetSymbolIDs = []artifacts.SymbolID{"cpp:core/kernel/ree_fs_ta.c:86:check_update_version()"}
	_, res := tryOpenAuditLead(recon, obs, p)
	if res.OK {
		t.Fatal("a lead targeting a symbol this pass never opened must be refused")
	}
	if !strings.Contains(res.Error, "check_update_version") {
		t.Errorf("the refusal must name the unopened target: %s", res.Error)
	}
	if !strings.Contains(res.Error, "get_function_card") {
		t.Errorf("the refusal must say how to fix it: %s", res.Error)
	}
}

// The gate blocks leads, not only done. Opening one function and raising a
// lead on it is how a Planner skips MAP entirely.
func TestOpenAuditLead_RefusedWhileReconnaissanceIsIncomplete(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_function_card", string(targetID), true)

	ref := MakeObservationRef("run-1", 0, 1, 0, "sha256:aaa")
	var obs ObservationSet
	obs.Record(ref, true)

	_, res := tryOpenAuditLead(r, obs, goodPayload(ref))
	if res.OK {
		t.Fatal("a lead raised after one function card must be refused")
	}
	if !strings.Contains(res.Error, "reconnaissance") {
		t.Errorf("the refusal must say the gate is what blocked it: %s", res.Error)
	}
	if !strings.Contains(res.Error, "get_repository_card") {
		t.Errorf("the refusal must say what would lift the gate: %s", res.Error)
	}
	if r.Phase() != PhaseReconnaissance {
		t.Error("a refused lead must not flip the phase")
	}
}

// Every problem at once. A model that learns its payload was malformed only
// after the gate lifts has spent a round to discover the second problem.
func TestOpenAuditLead_ReportsEveryProblemAtOnce(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	_, res := tryOpenAuditLead(r, ObservationSet{}, OpenAuditLeadPayload{})
	if res.OK {
		t.Fatal("an empty payload against a closed gate must be refused")
	}
	for _, want := range []string{"reconnaissance", "security_question", "target_symbol_ids", "reason_fact_refs"} {
		if !strings.Contains(res.Error, want) {
			t.Errorf("the refusal never mentions %s:\n%s", want, res.Error)
		}
	}
}

func TestOpenAuditLead_WritesTheLeadAndFlipsToInvestigation(t *testing.T) {
	recon, obs, ref := openedRecon(t, targetID)
	if recon.Phase() != PhaseReconnaissance {
		t.Fatal("a pass starts in reconnaissance")
	}

	lead, res := tryOpenAuditLead(recon, obs, goodPayload(ref))
	if !res.OK {
		t.Fatalf("a grounded lead must be accepted: %s", res.Error)
	}
	if lead.State != artifacts.LeadStateOpen {
		t.Errorf("state = %q, want open", lead.State)
	}
	if lead.SecurityQuestion == "" || len(lead.ReasonFactRefs) != 1 {
		t.Errorf("the lead lost its content: %+v", lead)
	}
	if recon.Phase() != PhaseInvestigation {
		t.Error("an accepted lead must flip the pass to investigation — that is the only way Pass B opens")
	}
	if recon.LeadsOpened() != 1 {
		t.Errorf("leads opened = %d, want 1", recon.LeadsOpened())
	}
}

// §6.4 requires that a question with no catalog mapping stays investigable.
// A lead describing a break this project has that no playbook names is not a
// lesser lead, and refusing it would make the TWE catalog a hard prerequisite
// for noticing anything.
func TestOpenAuditLead_AcceptsALeadWithNoRelatedTWE(t *testing.T) {
	recon, obs, ref := openedRecon(t, targetID)

	p := goodPayload(ref)
	p.RelatedTWEs = nil
	lead, res := tryOpenAuditLead(recon, obs, p)
	if !res.OK {
		t.Fatalf("related_twes must be allowed to be empty: %s", res.Error)
	}
	if len(lead.RelatedTWEs) != 0 {
		t.Errorf("related_twes = %v, want empty — nothing may invent a mapping", lead.RelatedTWEs)
	}
}

// Uncertainty is the Planner's confidence that the question is worth
// answering. A value nobody defined would arrive downstream reading like a
// severity.
func TestOpenAuditLead_RejectsAnUndefinedUncertainty(t *testing.T) {
	recon, obs, ref := openedRecon(t, targetID)

	p := goodPayload(ref)
	p.Uncertainty = "critical"
	_, res := tryOpenAuditLead(recon, obs, p)
	if res.OK {
		t.Fatal(`uncertainty "critical" must be refused — it is not a severity`)
	}
}
