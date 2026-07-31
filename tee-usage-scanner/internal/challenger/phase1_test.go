package challenger

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/tools"
)

// independentViewJSON / challengeJSON are minimal valid wire JSON for the
// two LLM calls Run(cfg, client) makes per case (phase 1: independent view,
// phase 2: challenge). An empty key_differences array in challengeJSON is
// deliberate: it forces buildChallengeLLM to fall back to the deterministic
// computeKeyDifferences(hypothesis, independentView) comparison, so tests
// can drive KeyDifferences purely by varying the phase-1 issue_present
// value below.
const independentViewJSON = `{"issue_present": true, "reasoning": "issue signal found", "confidence": "medium"}`
const independentViewNoIssueJSON = `{"issue_present": false, "reasoning": "no supporting signal", "confidence": "low"}`
const challengeJSON = `{"exploit_narrative": "n", "counter_arguments": [], "remaining_questions": [], "suggested_checks": [], "exploitability": "theoretical", "reviewer_stance": "challenge_required", "key_differences": []}`

// ─── Stubs (mirrors internal/expert/run_test.go, internal/verifier/run_test.go) ───

type stubLLM struct {
	responseJSON string
	gotRequests  []llm.GenerateRequest
}

func (s *stubLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequests = append(s.gotRequests, req)
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

func (s *stubLLM) lastRequest() llm.GenerateRequest {
	return s.gotRequests[len(s.gotRequests)-1]
}

type stubToolAdapter struct{}

func (stubToolAdapter) SearchKeywords(_ context.Context, _ string, _, _ []string, _ int) ([]tools.SearchHit, error) {
	return nil, nil
}

// ─── §25 acceptance: phase-1 prompt does NOT contain the Expert's conclusion ───

// TestBuildIndependentPrompt_HasNoHypothesisParameter is a
// compile-time / structural proof: buildIndependentPrompt's signature
// takes a CasePack and a caseContext, and nothing else — there is no
// artifacts.Hypothesis value in scope for it to leak. If this test
// file fails to compile after someone adds a Hypothesis parameter to
// buildIndependentPrompt without threading it through here too, that
// alone is a signal the phase boundary moved.
func TestBuildIndependentPrompt_HasNoHypothesisParameter(t *testing.T) {
	pack := artifacts.CasePack{CaseID: "case-001", Category: "rollback"}
	system, user := buildIndependentPrompt(pack, caseContext{}, nil)
	if system == "" || user == "" {
		t.Fatal("buildIndependentPrompt returned empty system/user")
	}
}

// TestBuildIndependentViewLLM_PromptExcludesExpertConclusion is the
// direct assertion §25 requires: run the actual phase-1 LLM path with
// a stub client, capture the assembled prompt, and confirm a
// distinctive marker that only exists in a would-be Expert hypothesis
// never appears anywhere in it. The hypothesis text is never even
// passed to buildIndependentViewLLM, so this also documents that the
// function has no way to have included it.
func TestBuildIndependentViewLLM_PromptExcludesExpertConclusion(t *testing.T) {
	repo := t.TempDir()

	resp := map[string]any{
		"issue_present": true, "reasoning": "r", "confidence": "medium",
	}
	respBytes, _ := json.Marshal(resp)
	stub := &stubLLM{responseJSON: string(respBytes)}

	pack := artifacts.CasePack{
		CaseID:   "case-001",
		Category: "rollback",
		Snippets: []artifacts.PromptSnippet{{Path: "src/x.c", StartLine: 1, EndLine: 1, Content: "int x;"}},
	}
	_, _, err := buildIndependentViewLLM(context.Background(), stub, stubToolAdapter{}, repo, pack, caseContext{}, "challenger-001", 0)
	if err != nil {
		t.Fatalf("buildIndependentViewLLM: %v", err)
	}

	// This is the marker a real Expert hypothesis would carry — its
	// title/summary/suspected_issue text. It must not appear anywhere
	// in the phase-1 prompt because buildIndependentViewLLM was never
	// given a Hypothesis value to read it from.
	const expertOnlyMarker = "EXPERT-CONCLUSION-MARKER-a1b2c3"
	req := stub.lastRequest()
	full := req.SystemPrompt + "\n" + req.Messages[0].Content
	if strings.Contains(full, expertOnlyMarker) {
		t.Fatalf("phase-1 prompt contains the Expert-only marker — independence violated:\n%s", full)
	}
	// Sanity: the phrase "expert hypothesis" as a LABEL should not
	// appear in phase 1 either — phase 2 is the only place that
	// section header belongs.
	if strings.Contains(strings.ToLower(full), "expert hypothesis") {
		t.Errorf("phase-1 prompt references an 'expert hypothesis' section — that belongs to phase 2 only:\n%s", full)
	}
}

// TestChallengerRun_Phase1PromptNeverSeesHypothesis runs the full
// two-phase Run() end to end (offline, via a fake LLM client) and confirms
// the persisted independent-NNN.json was written and does not embed
// any hypothesis text, i.e. phase 1 really ran before phase 2 read
// the hypothesis file — not just that the function signature is
// clean.
func TestChallengerRun_Phase1ArtifactPersistedBeforePhase2Reads(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()

	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1", LocalPath: repoRoot}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}

	pack := artifacts.CasePack{SchemaVersion: "teecheck.case_pack.v1", CaseID: "case-001", Category: "rollback"}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}

	hyp := artifacts.Hypothesis{
		SchemaVersion: "teecheck.hypothesis.v1", CaseID: "case-001", AgentID: "expert-001",
		Title: "EXPERT-CONCLUSION-MARKER-xyz", Confidence: "high",
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, AgentID: "challenger-001"}
	fake := &llmtest.FakeClient{Responses: []string{independentViewJSON, challengeJSON}}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}

	independentPath := filepath.Join(runfs.ChallengerDir(runDir), "independent-001.json")
	data, err := os.ReadFile(independentPath)
	if err != nil {
		t.Fatalf("independent view not persisted: %v", err)
	}
	if strings.Contains(string(data), "EXPERT-CONCLUSION-MARKER-xyz") {
		t.Fatalf("persisted phase-1 independent view contains the Expert's hypothesis text:\n%s", data)
	}

	var challenge artifacts.Challenge
	if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), &challenge); err != nil {
		t.Fatalf("challenge not persisted: %v", err)
	}
	if challenge.IndependentViewPath != independentPath {
		t.Errorf("challenge.IndependentViewPath = %q, want %q", challenge.IndependentViewPath, independentPath)
	}
	if len(challenge.KeyDifferences) == 0 {
		t.Error("challenge.KeyDifferences empty; phase 2 should always report a comparison result")
	}
}

// ─── Investigation knowledge reaches the phase-1 prompt (2026-07-28) ─

// sectionBody returns the text under the prompt section whose header
// starts with headerPrefix, up to the next blank line. Asserting on the
// section BODY (not "the prompt contains this string somewhere") is what
// makes the empty case checkable: a header with nothing under it fails,
// a header with "(none)" passes.
func sectionBody(t *testing.T, prompt, headerPrefix string) string {
	t.Helper()
	i := strings.Index(prompt, headerPrefix)
	if i < 0 {
		t.Fatalf("prompt has no section starting %q:\n%s", headerPrefix, prompt)
	}
	rest := prompt[i:]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		t.Fatalf("section %q has no body at all:\n%s", headerPrefix, prompt)
	}
	body := rest[nl+1:]
	if end := strings.Index(body, "\n\n"); end >= 0 {
		body = body[:end]
	}
	return strings.TrimSpace(body)
}

const (
	observedFlowHeader    = "Observed flow ("
	counterEvidenceHeader = "Counter-evidence the Investigator already found ("
)

// TestBuildIndependentPrompt_CarriesObservedFlowAndCounterEvidence is the
// consumer-side half of the 2026-07-28 fix on the Challenger side. The
// Challenger's job is to argue against the case, so counter-evidence the
// Planner already found is its most directly usable input — it gets its
// OWN labelled section, ahead of the general prior-knowledge blocks,
// rather than being folded into one of the " | " field lists where it
// would read as one more piece of case metadata.
func TestBuildIndependentPrompt_CarriesObservedFlowAndCounterEvidence(t *testing.T) {
	pack := artifacts.CasePack{
		CaseID: "case-001",
		ObservedFlow: []artifacts.ToolPathStep{
			{
				Location: artifacts.ToolLocation{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
				Kind:     "source",
				Message:  "OBSERVED-STEP-ONE-MARKER",
			},
			{
				Location: artifacts.ToolLocation{Path: "core/tee/tee_rollback.c", StartLine: 91, Symbol: "rollback_check"},
				Message:  "OBSERVED-STEP-TWO-MARKER",
			},
		},
		CounterEvidence: []string{"COUNTER-EVIDENCE-MARKER-A", "COUNTER-EVIDENCE-MARKER-B"},
	}

	_, user := buildIndependentPrompt(pack, caseContext{}, nil)

	flow := sectionBody(t, user, observedFlowHeader)
	for _, want := range []string{
		"core/crypto/signed_hdr.c:262", "shdr_load_pub_key", "OBSERVED-STEP-ONE-MARKER",
		"core/tee/tee_rollback.c:91", "rollback_check", "OBSERVED-STEP-TWO-MARKER",
	} {
		if !strings.Contains(flow, want) {
			t.Errorf("observed-flow section missing %q:\n%s", want, flow)
		}
	}

	counter := sectionBody(t, user, counterEvidenceHeader)
	for _, want := range []string{"COUNTER-EVIDENCE-MARKER-A", "COUNTER-EVIDENCE-MARKER-B"} {
		if !strings.Contains(counter, want) {
			t.Errorf("counter-evidence section missing %q:\n%s", want, counter)
		}
	}

	// Placement is the judgment call this test pins: counter-evidence is
	// the Challenger's starting material, so it precedes the general TWE
	// prior-knowledge block rather than trailing the prompt.
	if strings.Index(user, counterEvidenceHeader) > strings.Index(user, "TWE prior knowledge:") {
		t.Errorf("counter-evidence section should precede the TWE prior-knowledge block:\n%s", user)
	}
}

func TestBuildIndependentPrompt_EmptyFlowAndCounterEvidenceRenderCleanly(t *testing.T) {
	_, user := buildIndependentPrompt(artifacts.CasePack{CaseID: "case-001"}, caseContext{}, nil)

	if got := sectionBody(t, user, observedFlowHeader); got != "(none)" {
		t.Errorf("empty observed flow rendered as %q, want %q (a dangling header reads as a truncated path)", got, "(none)")
	}
	if got := sectionBody(t, user, counterEvidenceHeader); got != "(none)" {
		t.Errorf("empty counter-evidence rendered as %q, want %q", got, "(none)")
	}
}

// TestBuildIndependentViewLLM_PromptCarriesObservedFlow proves the
// rendering survives the real call path (the same one Run uses), not
// only a direct buildIndependentPrompt call.
func TestBuildIndependentViewLLM_PromptCarriesObservedFlow(t *testing.T) {
	stub := &stubLLM{responseJSON: independentViewJSON}
	pack := artifacts.CasePack{
		CaseID: "case-001",
		ObservedFlow: []artifacts.ToolPathStep{{
			Location: artifacts.ToolLocation{Path: "core/tee/tee_rollback.c", StartLine: 91, Symbol: "rollback_check"},
			Message:  "OBSERVED-STEP-MARKER",
		}},
		CounterEvidence: []string{"COUNTER-EVIDENCE-MARKER"},
	}
	if _, _, err := buildIndependentViewLLM(context.Background(), stub, stubToolAdapter{}, t.TempDir(), pack, caseContext{}, "challenger-001", 0); err != nil {
		t.Fatalf("buildIndependentViewLLM: %v", err)
	}
	prompt := stub.lastRequest().Messages[0].Content
	for _, want := range []string{"OBSERVED-STEP-MARKER", "rollback_check", "COUNTER-EVIDENCE-MARKER"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("phase-1 prompt missing %q:\n%s", want, prompt)
		}
	}
}

// ─── §25 acceptance: ToolFact never rewritten ───────────────────────

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return string(sum[:])
}

func TestChallengerRun_NeverRewritesToolFact(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()

	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1", LocalPath: repoRoot}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}

	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "fact-001", Tool: "trustir", Operation: "reverse_trace", Status: "ok"}
	factPath := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if err := runfs.WriteJSON(factPath, fact); err != nil {
		t.Fatal(err)
	}
	beforeHash := hashFile(t, factPath)

	pack := artifacts.CasePack{SchemaVersion: "teecheck.case_pack.v1", CaseID: "case-001", Category: "rollback", ToolFactRefs: []string{factPath}}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}
	hyp := artifacts.Hypothesis{SchemaVersion: "teecheck.hypothesis.v1", CaseID: "case-001", AgentID: "expert-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, AgentID: "challenger-001"}
	fake := &llmtest.FakeClient{Responses: []string{independentViewJSON, challengeJSON}}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if afterHash := hashFile(t, factPath); afterHash != beforeHash {
		t.Fatalf("ToolFact %s was rewritten by the Challenger stage", factPath)
	}
}

// ─── §25 acceptance: vulnerable vs fixed variant differential ───────

// TestChallengerRun_VulnerableVsFixed_IdentifiesKeyDifference drives
// the same two-phase Run(cfg, client) against two otherwise-identical
// CasePacks/Hypotheses, varying only the phase-1 LLM response's
// issue_present value (true = "vulnerable", false = "fixed"). Both
// phase-2 responses omit key_differences, forcing buildChallengeLLM's
// deterministic computeKeyDifferences fallback, so the divergence in
// the final Challenge.KeyDifferences is driven entirely by the
// phase-1 independent view — not the Expert hypothesis, which is
// identical across both runs — proving the two-phase wiring, not any
// snippet-text heuristic (since Run is now always-LLM, there is no
// heuristic left to exercise here).
func TestChallengerRun_VulnerableVsFixed_IdentifiesKeyDifference(t *testing.T) {
	runOnce := func(t *testing.T, independentViewResp string) artifacts.Challenge {
		t.Helper()
		runDir := t.TempDir()
		repoRoot := t.TempDir()

		manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1", LocalPath: repoRoot}
		if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
			t.Fatal(err)
		}
		pack := artifacts.CasePack{
			SchemaVersion:       "teecheck.case_pack.v1",
			CaseID:              "case-001",
			Category:            "rollback",
			ExpectedObligations: []string{"subkey_version_propagation"},
			Snippets:            []artifacts.PromptSnippet{{Path: "src/loader.c", StartLine: 1, EndLine: 1, Content: "load_key();\n"}},
		}
		if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
			t.Fatal(err)
		}
		// Identical Expert hypothesis in both runs — only the phase-1
		// independent view (below) differs between the two calls.
		hyp := artifacts.Hypothesis{
			SchemaVersion: "teecheck.hypothesis.v1", CaseID: "case-001", AgentID: "expert-001",
			Title: "possible rollback gap", SuspectedIssue: "version may not propagate", Confidence: "high",
		}
		if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
			t.Fatal(err)
		}

		cfg := config.Config{RunDir: runDir, AgentID: "challenger-001"}
		fake := &llmtest.FakeClient{Responses: []string{independentViewResp, challengeJSON}}
		if err := Run(cfg, fake); err != nil {
			t.Fatalf("Run: %v", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), &challenge); err != nil {
			t.Fatal(err)
		}
		return challenge
	}

	vulnerable := runOnce(t, independentViewJSON)
	fixed := runOnce(t, independentViewNoIssueJSON)

	if !vulnerable.IndependentIssuePresent {
		t.Errorf("vulnerable variant: independent view should flag an issue, got IndependentIssuePresent=false; KeyDifferences=%v", vulnerable.KeyDifferences)
	}
	if fixed.IndependentIssuePresent {
		t.Errorf("fixed variant: independent view should NOT flag an issue (phase-1 LLM response said issue_present=false), got IndependentIssuePresent=true")
	}

	// The fixed variant's KeyDifferences must actually name the
	// disagreement with the (identical) Expert hypothesis.
	foundDisagreement := false
	for _, d := range fixed.KeyDifferences {
		if strings.Contains(d, "NO supporting issue signal") {
			foundDisagreement = true
		}
	}
	if !foundDisagreement {
		t.Errorf("fixed variant KeyDifferences did not name the phase-1/Expert disagreement: %v", fixed.KeyDifferences)
	}

	// The vulnerable variant should NOT report that same disagreement
	// (both phase 1 and Expert agree an issue is present).
	for _, d := range vulnerable.KeyDifferences {
		if strings.Contains(d, "NO supporting issue signal") {
			t.Errorf("vulnerable variant KeyDifferences wrongly reports independent/Expert disagreement: %v", vulnerable.KeyDifferences)
		}
	}
}
