package planner_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// reconBudget is the production shape: reconnaissance rounds granted on top
// of the investigation budget. defaultTestBudget grants none, which is what
// keeps the pre-reconnaissance tests testing what they always tested.
func reconBudget() planner.Budget {
	return planner.Budget{
		MaxRounds:        8,
		MaxReconRounds:   6,
		MaxTokens:        200000,
		PerActionTimeout: 30 * time.Second,
		WallClock:        10 * time.Minute,
	}
}

// writeProjectMap puts a browsable map in the run dir. Its presence is what
// tells the planner the reconnaissance stage ran at all.
func writeProjectMap(t *testing.T, runDir string, modules ...artifacts.ModuleCard) {
	t.Helper()
	m := artifacts.ProjectMap{
		SchemaVersion: "teecheck.project_map.v1",
		RunID:         "test",
		Modules:       modules,
	}
	m.Capabilities.Symbols = artifacts.CapabilityAvailable
	m.Repository.FileCount = 40
	if err := runfs.WriteJSON(runfs.ProjectMapPath(runDir), m); err != nil {
		t.Fatal(err)
	}
}

func readAuditLeads(t *testing.T, runDir string) []artifacts.AuditLead {
	t.Helper()
	f, err := os.Open(runfs.AuditLeadsPath(runDir))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []artifacts.AuditLead
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var lead artifacts.AuditLead
		if err := json.Unmarshal(sc.Bytes(), &lead); err != nil {
			t.Fatalf("audit_leads.jsonl line is not a lead: %v", err)
		}
		out = append(out, lead)
	}
	return out
}

func readLedger(t *testing.T, runDir string) artifacts.CoverageLedger {
	t.Helper()
	var l artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(runDir), &l); err != nil {
		t.Fatalf("read coverage ledger: %v", err)
	}
	return l
}

// allRoundObservations flattens every round in rounds.jsonl.
func allRoundObservations(t *testing.T, runDir string) []artifacts.RoundObservation {
	t.Helper()
	data, err := os.ReadFile(runfs.RoundsLogPath(runDir))
	if err != nil {
		t.Fatalf("read rounds.jsonl: %v", err)
	}
	var out []artifacts.RoundObservation
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r artifacts.RoundRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("unmarshal round: %v", err)
		}
		out = append(out, r.Observations...)
	}
	return out
}

// Pass A must be project-first by construction. An instruction the model can
// ignore is not a constraint — on run-b the planner's very first two actions
// were twe_playbook_detail calls, because the catalog sat at the top of its
// prompt.
func TestPassA_RefusesTWEPlaybookDetail(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, artifacts.ModuleCard{Path: "core", FunctionCount: 3})

	client := &mockLLM{scripts: []string{
		`{"thought":"pull the playbook","actions":[{"name":"twe_playbook_detail","args":{"twe_id":"TWE-STATE-001"}}]}`,
	}}

	reg := actions.NewDefaultRegistryWithNav()
	reg.Register(&actions.TWEPlaybookDetailHandler{})
	if !reg.Has("twe_playbook_detail") {
		t.Fatal("the full registry must carry it — Pass B is what restores it")
	}

	planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-passa", RepoRoot: repoRoot, RunDir: runDir,
		Profile: planner.PromptProfile{Focus: "tee"},
		Client:  client, Registry: reg, Budget: reconBudget(),
	})

	if strings.Contains(client.sent[0].SystemPrompt, "twe_playbook_detail") {
		t.Error("the reconnaissance prompt advertises twe_playbook_detail")
	}
	obs := allRoundObservations(t, runDir)
	if len(obs) == 0 {
		t.Fatal("no observations recorded")
	}
	if obs[0].OK || !strings.Contains(obs[0].Error, "unknown action") {
		t.Errorf("twe_playbook_detail was reachable during Pass A: %+v", obs[0])
	}
}

// The gate blocks `done`, and the refusal has to say what would lift it —
// otherwise it is a wall the model can only hit repeatedly.
func TestReconnaissanceGate_RefusesDoneAndSaysWhatIsMissing(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, fiveModules()...)

	client := &mockLLM{scripts: []string{
		`{"thought":"conclude","actions":[{"name":"done","args":{"summary":"x","candidates":[]}}]}`,
	}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-gate", RepoRoot: repoRoot, RunDir: runDir,
		Profile: planner.PromptProfile{Focus: "tee"},
		Client:  client, Registry: actions.NewDefaultRegistryWithNav(),
		Budget: reconBudget(),
	})

	obs := allRoundObservations(t, runDir)
	if len(obs) == 0 || obs[0].OK {
		t.Fatalf("round 1: done must be refused, got %+v", obs)
	}
	for _, want := range []string{"get_repository_card", "list_functions", "get_function_card", "get_callers"} {
		if !strings.Contains(obs[0].Error, want) {
			t.Errorf("the refusal never names %s:\n%s", want, obs[0].Error)
		}
	}
	if result.Bundle.PlannerMeta.TerminationReason == "llm_done" {
		t.Error("a run whose done was refused in round 1 must not report llm_done")
	}
}

// Neither escape may be silent. A pass released because its browsing rounds
// ran out did not conclude for the same reason as one that finished looking,
// and §6.5 requires everything unopened to be recorded as a coverage gap.
func TestReconnaissance_TheBudgetEscapeIsRecordedInTheLedger(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, fiveModules()...)

	browse := `{"thought":"look","actions":[{"name":"get_repository_card","args":{}}]}`
	client := &mockLLM{scripts: []string{browse}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-escape", RepoRoot: repoRoot, RunDir: runDir,
		SampleIndex: 1,
		Profile:     planner.PromptProfile{Focus: "tee"},
		Client:      client, Registry: actions.NewDefaultRegistryWithNav(),
		Budget: reconBudget(),
	})
	if result.Err != nil {
		t.Fatalf("planner: %v", result.Err)
	}

	ledger := readLedger(t, runDir)
	if len(ledger.BySample) != 1 {
		t.Fatalf("ledger by_sample = %+v, want one entry", ledger.BySample)
	}
	s := ledger.BySample[0]
	if s.SampleIndex != 1 {
		t.Errorf("sample_index = %d, want the pass the planner was driving", s.SampleIndex)
	}
	if s.ReconStatus != "recon_budget_exhausted" {
		t.Errorf("recon_status = %q — the escape must be recorded, never silent", s.ReconStatus)
	}
	if s.ReconRoundsUsed != 6 {
		t.Errorf("recon_rounds_used = %d, want the full allowance", s.ReconRoundsUsed)
	}
	if len(ledger.UnreviewedClusters) != 5 {
		t.Errorf("unreviewed_clusters = %v, want all five — none was reviewed", ledger.UnreviewedClusters)
	}
	if ledger.ModulesTotal != 5 || ledger.ModulesReviewed != 0 {
		t.Errorf("ledger reviewed %d of %d modules, want 0 of 5", ledger.ModulesReviewed, ledger.ModulesTotal)
	}
}

// A lead reaches disk with its identity stamped, cites a ref the planner
// actually printed, and flips the run into Pass B. That flip is the only way
// Pass B opens.
func TestOpenAuditLead_PersistsAndOpensPassB(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, fiveModules()...)

	const target = "cpp:core/loader.c:14:load_pub_key()"
	lead := `{"thought":"ask","actions":[{"name":"open_audit_lead","args":{
	  "security_question":"does the loader check what the verifier verified?",
	  "target_symbol_ids":["` + target + `"],
	  "reason":["the card shows no write to the field the consumer reads"],
	  "reason_fact_refs":["REF"],
	  "uncertainty":"high"}}]}`

	client := &leadLLM{
		target: target,
		lead:   lead,
		done:   `{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[]}}]}`,
	}

	reg := actions.NewDefaultRegistryWithNav()
	reg.Register(&actions.TWEPlaybookDetailHandler{})
	reg.Register(stubCardHandler{}) // stands in for a built index

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-lead", RepoRoot: repoRoot, RunDir: runDir,
		Profile:    planner.PromptProfile{Focus: "tee"},
		TWEContext: "[TWE-STATE-001] Trusted State Rollback | family=State\n",
		Client:     client, Registry: reg, Budget: reconBudget(),
	})
	if result.Err != nil {
		t.Fatalf("planner: %v", result.Err)
	}

	leads := readAuditLeads(t, runDir)
	if len(leads) != 1 {
		var refusals []string
		for _, o := range allRoundObservations(t, runDir) {
			if o.Name == "open_audit_lead" && !o.OK {
				refusals = append(refusals, o.Error)
			}
		}
		t.Fatalf("audit leads = %d, want 1; refusals: %v", len(leads), refusals)
	}
	got := leads[0]
	if got.LeadID == "" || got.RunID != "test-lead" || got.State != artifacts.LeadStateOpen {
		t.Errorf("the lead lost its identity: %+v", got)
	}
	if got.OpenedAtRound == 0 {
		t.Error("the lead does not say which round raised it")
	}
	if len(got.ReasonFactRefs) != 1 || !strings.HasPrefix(got.ReasonFactRefs[0], "obs:") {
		t.Errorf("reason_fact_refs = %v, want the observation ref it cited", got.ReasonFactRefs)
	}
	if len(got.RelatedTWEs) != 0 {
		t.Errorf("related_twes = %v — §6.4 allows it empty and nothing may invent a mapping", got.RelatedTWEs)
	}

	// Every cited ref resolves to a successful observation in the rounds log.
	// This is the acceptance criterion, checked the way a reader would.
	grounded := map[string]bool{}
	for _, o := range allRoundObservations(t, runDir) {
		if o.OK && o.Ref != "" {
			grounded[o.Ref] = true
		}
	}
	for _, ref := range got.ReasonFactRefs {
		if !grounded[ref] {
			t.Errorf("cited ref %q is not a successful observation in rounds.jsonl", ref)
		}
	}

	// The catalog is absent while the Planner is reading the project and
	// present once it has a question of its own. This is the end-to-end
	// half: BuildSystemPrompt honouring the phase proves nothing if the loop
	// hands it the wrong one.
	first := client.sent[0].SystemPrompt
	for _, banned := range []string{"TWE-STATE-001", "TWE PRIOR KNOWLEDGE", "twe_playbook_detail"} {
		if strings.Contains(first, banned) {
			t.Errorf("the round-1 prompt carries %q — Pass A is primed", banned)
		}
	}
	last := client.sent[len(client.sent)-1].SystemPrompt
	for _, want := range []string{"TWE-STATE-001", "twe_playbook_detail",
		"You have opened an audit lead of your own"} {
		if !strings.Contains(last, want) {
			t.Errorf("Pass B never opened: the final prompt is missing %q", want)
		}
	}

	for _, o := range allRoundObservations(t, runDir) {
		if o.Name == "open_audit_lead" && o.OK && o.Phase != planner.PhaseReconnaissance {
			t.Errorf("the lead was tagged %q; it is the action that ENDS reconnaissance", o.Phase)
		}
	}

	ledger := readLedger(t, runDir)
	if ledger.LeadsOpen != 1 {
		t.Errorf("ledger leads_open = %d, want 1", ledger.LeadsOpen)
	}
	if ledger.FunctionCapsulesReviewed == 0 {
		t.Error("the ledger credits no capsule to a pass that opened several")
	}
}

func fiveModules() []artifacts.ModuleCard {
	return []artifacts.ModuleCard{
		{Path: "core", FunctionCount: 40},
		{Path: "lib", FunctionCount: 40},
		{Path: "ta", FunctionCount: 40},
		{Path: "ldelf", FunctionCount: 40},
		{Path: "mk", FunctionCount: 40},
	}
}

// stubCardHandler stands in for a built program index: get_function_card
// answers, so the pass has a symbol it genuinely opened and a ref it can
// genuinely cite.
type stubCardHandler struct{}

func (stubCardHandler) Name() string { return "get_function_card" }
func (stubCardHandler) Run(context.Context, actions.ActionRequest) actions.ActionResult {
	return actions.ActionResult{
		Name:   "get_function_card",
		OK:     true,
		Output: "name: load_pub_key\ncalled_by: (none resolved)\nfield_accesses: pub_key.max_depth\n",
	}
}

// leadLLM browses until the gate opens, then raises its lead citing the ref
// the planner printed for the observation it is citing.
//
// It varies its browsing every round because the loop detector rejects a
// repeated (action, args) tuple — and a rejected action produces no
// observation and therefore no ref, so a model stuck repeating itself loses
// the very evidence it would need to cite. That is the real behaviour, not
// a test artifact.
type leadLLM struct {
	target, lead, done string
	sent               []llm.GenerateRequest
	firstRef           string
	openedLead         bool
	round              int
}

func (m *leadLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	m.sent = append(m.sent, req)
	body := req.Messages[0].Content
	m.round++

	// A real model remembers the refs it was shown; this one keeps the
	// first, which is the card for the symbol its lead is about.
	if m.firstRef == "" {
		m.firstRef = firstRefIn(body)
	}

	if m.openedLead {
		return llm.GenerateResponse{Text: m.done}, nil
	}
	released := strings.Contains(body, "You have seen enough of this project") ||
		strings.Contains(body, "reconnaissance rounds are spent")
	if released && m.firstRef != "" {
		m.openedLead = true
		return llm.GenerateResponse{Text: strings.Replace(m.lead, "REF", m.firstRef, 1)}, nil
	}

	symbol := m.target
	if m.round > 1 {
		symbol = fmt.Sprintf("cpp:lib/other%d.c:1:helper%d()", m.round, m.round)
	}
	return llm.GenerateResponse{Text: fmt.Sprintf(
		`{"thought":"look","actions":[{"name":"get_function_card","args":{"symbol_id":%q}}]}`, symbol)}, nil
}

// firstRefIn pulls the earliest ref= the prompt printed.
func firstRefIn(prompt string) string {
	for _, line := range strings.Split(prompt, "\n") {
		if i := strings.Index(line, "ref=obs:"); i >= 0 {
			return strings.TrimSpace(line[i+len("ref="):])
		}
	}
	return ""
}

// The reconnaissance block is the last thing in the round prompt, so it is
// the last instruction the model reads. On the first real run against OP-TEE
// it ended with a checklist of things still to do — and the model replied
// with prose describing what it was about to do, twice in a row. The run
// died on round 6 with llm_malformed.
func TestReconStatusBlock_EndsWithTheResponseFormat(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, fiveModules()...)

	client := &mockLLM{scripts: []string{
		`{"thought":"look","actions":[{"name":"get_repository_card","args":{}}]}`,
	}}
	planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-blocktail", RepoRoot: repoRoot, RunDir: runDir,
		Profile: planner.PromptProfile{Focus: "tee"},
		Client:  client, Registry: actions.NewDefaultRegistryWithNav(),
		Budget: reconBudget(),
	})

	body := client.sent[0].Messages[0].Content
	if !strings.Contains(body, "=== RECONNAISSANCE ===") {
		t.Fatal("the round prompt carries no reconnaissance block")
	}
	tail := body[strings.LastIndex(body, "=== RECONNAISSANCE ==="):]
	if !strings.Contains(tail, "JSON object") {
		t.Errorf("the last thing the model reads must say how to answer:\n%s", tail)
	}
}

// Once the budget escape has fired, what is unmet is history rather than a
// precondition. The first real run printed both "you still need to" and "the
// gate is no longer blocking" in consecutive sentences.
func TestReconStatusBlock_TheEscapeDoesNotContradictTheChecklist(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeProjectMap(t, runDir, fiveModules()...)

	client := &mockLLM{scripts: []string{
		`{"thought":"look","actions":[{"name":"get_repository_card","args":{}}]}`,
	}}
	planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-escape-text", RepoRoot: repoRoot, RunDir: runDir,
		Profile: planner.PromptProfile{Focus: "tee"},
		Client:  client, Registry: actions.NewDefaultRegistryWithNav(),
		Budget: reconBudget(),
	})

	// The last round is the one where the allowance ran out.
	last := client.sent[len(client.sent)-1].Messages[0].Content
	tail := last[strings.LastIndex(last, "=== RECONNAISSANCE ==="):]
	if !strings.Contains(tail, "no longer blocking") {
		t.Fatalf("the escape must be stated:\n%s", tail)
	}
	if strings.Contains(tail, "Before you can open a lead") {
		t.Errorf("the released gate still prints its own precondition:\n%s", tail)
	}
}
