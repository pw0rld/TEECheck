package challenger

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// captureRecorder is an in-memory events.Recorder for assertions.
type captureRecorder struct{ emitted []events.Event }

func (c *captureRecorder) Emit(e events.Event) error { c.emitted = append(c.emitted, e); return nil }
func (c *captureRecorder) Close() error              { return nil }

// ─── Regression suite for the "synthetic echo" defect ────────────────
//
// Until 2026-07-28 the Challenger ran BOTH of its rating fields through
// a single normalizeExploitability(value, expertConfidence) helper:
//
//   - phase 1 asks the model for "low"|"medium"|"high" and normalized
//     against the exploitability whitelist, so every legal answer fell
//     through to "theoretical" — on every run, deterministically;
//   - phase 2 fell back to the EXPERT's confidence when the model's
//     exploitability text did not match, i.e. the one field whose job is
//     independent judgement was filled with the judgement it exists to
//     challenge.
//
// The tests below are the assertions that did not exist: a round trip
// per legal value per field, the bounded corrective re-ask, the
// unrated fallback (explicitly NOT the Expert's confidence), and the
// run-directory record of the rewrite.

// expertConfidenceInFixtures is the value every fixture below gives the
// Expert hypothesis. It is deliberately a legal *confidence* value, so
// a regression to the old cross-agent fallback would make the
// Challenger's own fields echo it and fail loudly.
const expertConfidenceInFixtures = "high"

// challengerRunFixture writes a minimal run dir (manifest + one case
// pack + one Expert hypothesis whose confidence is "high") and returns
// the run dir.
func challengerRunFixture(t *testing.T) string {
	t.Helper()
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
		Title: "possible rollback gap", Confidence: expertConfidenceInFixtures,
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
		t.Fatal(err)
	}
	return runDir
}

func phase1Reply(confidence string) string {
	return fmt.Sprintf(`{"issue_present": true, "reasoning": "issue signal found", "confidence": %q}`, confidence)
}

func phase2Reply(exploitability string) string {
	return fmt.Sprintf(`{"exploit_narrative": "n", "counter_arguments": [], "remaining_questions": [], "suggested_checks": [], "exploitability": %q, "reviewer_stance": "challenge_required", "key_differences": ["d"]}`, exploitability)
}

// runChallenger drives the real two-phase Run against a queued fake
// client and returns the persisted artifacts plus the client (for call
// counting / prompt assertions).
func runChallenger(t *testing.T, replies ...string) (string, artifacts.ChallengerIndependentView, artifacts.Challenge, *llmtest.FakeClient) {
	t.Helper()
	runDir := challengerRunFixture(t)
	fake := &llmtest.FakeClient{Responses: replies}
	cfg := config.Config{RunDir: runDir, AgentID: "challenger-001"}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var independent artifacts.ChallengerIndependentView
	if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(runDir), "independent-001.json"), &independent); err != nil {
		t.Fatalf("read independent view: %v", err)
	}
	var challenge artifacts.Challenge
	if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), &challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	return runDir, independent, challenge, fake
}

// ─── Round trip: every legal value survives to the artifact ──────────

func TestChallengerRun_Phase1ConfidenceRoundTrips(t *testing.T) {
	for _, want := range []string{"low", "medium", "high"} {
		t.Run(want, func(t *testing.T) {
			_, independent, _, fake := runChallenger(t, phase1Reply(want), phase2Reply("likely"))
			if independent.Confidence != want {
				t.Fatalf("model said confidence %q, artifact recorded %q", want, independent.Confidence)
			}
			if len(fake.Calls) != 2 {
				t.Errorf("expected exactly 2 LLM calls (no re-ask on a legal value), got %d", len(fake.Calls))
			}
		})
	}
}

func TestChallengerRun_Phase2ExploitabilityRoundTrips(t *testing.T) {
	for _, want := range []string{"proven", "likely", "theoretical", "unlikely"} {
		t.Run(want, func(t *testing.T) {
			_, _, challenge, fake := runChallenger(t, phase1Reply("medium"), phase2Reply(want))
			if challenge.Exploitability != want {
				t.Fatalf("model said exploitability %q, artifact recorded %q", want, challenge.Exploitability)
			}
			if len(fake.Calls) != 2 {
				t.Errorf("expected exactly 2 LLM calls (no re-ask on a legal value), got %d", len(fake.Calls))
			}
		})
	}
}

// TestChallengerRun_VocabulariesAreNotInterchangeable pins the split:
// a confidence word is not a legal exploitability value and vice versa.
// The merged normalizer accepted the exploitability set on BOTH fields,
// which is exactly how "high" became "theoretical".
func TestChallengerRun_VocabulariesAreNotInterchangeable(t *testing.T) {
	// "likely" is legal exploitability, illegal confidence: phase 1 must
	// reject it and re-ask.
	_, independent, _, fake := runChallenger(t,
		phase1Reply("likely"), phase1Reply("high"), phase2Reply("proven"))
	if independent.Confidence != "high" {
		t.Errorf("phase-1 confidence = %q; %q is an exploitability word and must not be accepted as confidence", independent.Confidence, "likely")
	}
	if len(fake.Calls) != 3 {
		t.Errorf("expected 3 calls (phase1 + one re-ask + phase2), got %d", len(fake.Calls))
	}

	// "high" is legal confidence, illegal exploitability: phase 2 must
	// reject it and re-ask.
	_, _, challenge, fake2 := runChallenger(t,
		phase1Reply("high"), phase2Reply("high"), phase2Reply("unlikely"))
	if challenge.Exploitability != "unlikely" {
		t.Errorf("phase-2 exploitability = %q; %q is a confidence word and must not be accepted as exploitability", challenge.Exploitability, "high")
	}
	if len(fake2.Calls) != 3 {
		t.Errorf("expected 3 calls (phase1 + phase2 + one re-ask), got %d", len(fake2.Calls))
	}
}

// ─── The bounded corrective re-ask ───────────────────────────────────

func TestChallengerRun_IllegalValueTriggersOneReaskThatRecovers(t *testing.T) {
	_, independent, challenge, fake := runChallenger(t,
		phase1Reply("quite sure"), phase1Reply("medium"),
		phase2Reply("moderate"), phase2Reply("proven"))

	if independent.Confidence != "medium" {
		t.Errorf("recovered phase-1 confidence = %q, want %q", independent.Confidence, "medium")
	}
	if challenge.Exploitability != "proven" {
		t.Errorf("recovered phase-2 exploitability = %q, want %q", challenge.Exploitability, "proven")
	}
	if len(fake.Calls) != 4 {
		t.Fatalf("expected 4 calls (one re-ask per phase), got %d", len(fake.Calls))
	}

	// The re-ask must tell the model it was rejected and quote the
	// offending value back (the internal/planner corrective shape).
	retry := fake.Calls[1].Messages[0].Content
	if !strings.Contains(retry, "YOUR PREVIOUS REPLY WAS REJECTED") {
		t.Errorf("phase-1 re-ask prompt lacks the rejection notice:\n%s", retry)
	}
	if !strings.Contains(retry, "quite sure") {
		t.Errorf("phase-1 re-ask prompt does not quote the rejected value back:\n%s", retry)
	}
	if !strings.Contains(retry, "low") || !strings.Contains(retry, "high") {
		t.Errorf("phase-1 re-ask prompt does not name the legal vocabulary:\n%s", retry)
	}
}

// TestChallengerRun_ReaskIsBoundedAtOne: two illegal replies in a row is
// a real failure, not something to spend budget on.
func TestChallengerRun_ReaskIsBoundedAtOne(t *testing.T) {
	_, _, _, fake := runChallenger(t,
		phase1Reply("quite sure"), phase1Reply("still not a scale"),
		phase2Reply("moderate"), phase2Reply("sort of"))
	if len(fake.Calls) != 4 {
		t.Fatalf("expected exactly 4 calls (2 phases x at most one re-ask each), got %d", len(fake.Calls))
	}
}

// ─── The unrated fallback — and specifically NOT the Expert's value ──

func TestChallengerRun_TwoIllegalRepliesPersistUnratedNotExpertConfidence(t *testing.T) {
	_, independent, challenge, _ := runChallenger(t,
		phase1Reply("quite sure"), phase1Reply("still not a scale"),
		phase2Reply("moderate"), phase2Reply("sort of"))

	if independent.Confidence != ratingUnrated {
		t.Errorf("phase-1 confidence = %q, want %q", independent.Confidence, ratingUnrated)
	}
	if challenge.Exploitability != ratingUnrated {
		t.Errorf("phase-2 exploitability = %q, want %q", challenge.Exploitability, ratingUnrated)
	}

	// The regression guard. The Expert hypothesis in the fixture says
	// "high"; the old code turned that into "likely" on the
	// exploitability field and into a silent "theoretical" on
	// confidence. An unparseable Challenger judgement is missing data,
	// never another agent's judgement.
	if independent.Confidence == expertConfidenceInFixtures {
		t.Errorf("phase-1 confidence echoes the Expert's confidence %q — the cross-agent fallback is back", expertConfidenceInFixtures)
	}
	for _, borrowed := range []string{"likely", "theoretical"} {
		if challenge.Exploitability == borrowed {
			t.Errorf("phase-2 exploitability = %q — derived from the Expert's confidence %q rather than recorded as missing data", borrowed, expertConfidenceInFixtures)
		}
	}
}

// TestChallengerRun_UnratedIsLegibleInThePhase2Prompt closes the
// feedback loop that made the original defect cascade: the phase-2
// prompt renders the phase-1 value back to the model as "your phase-1
// independent view", so a rewritten value there makes the model reason
// from a premise it never held. An unrated value must read as unrated.
func TestChallengerRun_UnratedIsLegibleInThePhase2Prompt(t *testing.T) {
	_, _, _, fake := runChallenger(t,
		phase1Reply("quite sure"), phase1Reply("still not a scale"),
		phase2Reply("likely"))

	phase2Prompt := fake.Calls[2].Messages[0].Content
	i := strings.Index(phase2Prompt, "- confidence:")
	if i < 0 {
		t.Fatalf("phase-2 prompt has no phase-1 confidence line:\n%s", phase2Prompt)
	}
	line := phase2Prompt[i:]
	if nl := strings.Index(line, "\n"); nl >= 0 {
		line = line[:nl]
	}
	if !strings.Contains(line, ratingUnrated) || !strings.Contains(line, "missing data") {
		t.Errorf("phase-2 prompt renders the unrated phase-1 confidence as %q; it must read as missing data, not as a blank or a verdict", line)
	}
	for _, verdict := range []string{"low", "medium", "high"} {
		if strings.Contains(line, ": "+verdict) {
			t.Errorf("phase-2 prompt shows a fabricated phase-1 confidence %q: %q", verdict, line)
		}
	}
}

// ─── Part 2: the rewrite must leave a trace in the run directory ─────

// TestChallengerRun_RecordsRewriteInRunDirectory is the test of a good
// answer to "could someone reading only the run directory discover that
// a value was rewritten, and what it was before?".
func TestChallengerRun_RecordsRewriteInRunDirectory(t *testing.T) {
	runDir, _, _, _ := runChallenger(t,
		phase1Reply("quite sure"), phase1Reply("medium"),
		phase2Reply("moderate"), phase2Reply("sort of"))

	var rec artifacts.ChallengerNormalizations
	path := runfs.ChallengerNormalizationsPath(runDir)
	if err := runfs.ReadJSON(path, &rec); err != nil {
		t.Fatalf("no normalization record in the run directory (%s): %v", path, err)
	}

	// Phase 1: recovered by the re-ask. Phase 2: fell back to unrated.
	var gotConfidence, gotExploitability bool
	for _, adj := range rec.Adjustments {
		if adj.CaseID != "case-001" {
			t.Errorf("adjustment not attributed to the case: %+v", adj)
		}
		switch adj.Field {
		case "confidence":
			gotConfidence = true
			if adj.Kind != "reask_recovered" {
				t.Errorf("confidence adjustment kind = %q, want %q", adj.Kind, "reask_recovered")
			}
			if adj.From != "quite sure" || adj.To != "medium" {
				t.Errorf("confidence adjustment does not carry both values: from=%q to=%q", adj.From, adj.To)
			}
		case "exploitability":
			gotExploitability = true
			if adj.Kind != "unrated_fallback" {
				t.Errorf("exploitability adjustment kind = %q, want %q", adj.Kind, "unrated_fallback")
			}
			if adj.From != "moderate" || adj.To != ratingUnrated {
				t.Errorf("exploitability adjustment does not carry both values: from=%q to=%q", adj.From, adj.To)
			}
			if !strings.Contains(adj.Reason, "sort of") {
				t.Errorf("reason does not mention the rejected re-ask value: %q", adj.Reason)
			}
		default:
			t.Errorf("unexpected adjustment field %q", adj.Field)
		}
		if adj.Reason == "" {
			t.Errorf("adjustment has no reason: %+v", adj)
		}
	}
	if !gotConfidence {
		t.Error("no record that the phase-1 confidence was replaced")
	}
	if !gotExploitability {
		t.Error("no record that the phase-2 exploitability was replaced")
	}
}

// A clean run still writes the record file, so a reader can tell
// "nothing was rewritten" apart from "this run predates the record".
func TestChallengerRun_WritesEmptyNormalizationRecordOnCleanRun(t *testing.T) {
	runDir, _, _, _ := runChallenger(t, phase1Reply("high"), phase2Reply("likely"))
	var rec artifacts.ChallengerNormalizations
	if err := runfs.ReadJSON(runfs.ChallengerNormalizationsPath(runDir), &rec); err != nil {
		t.Fatalf("clean run wrote no normalization record: %v", err)
	}
	if len(rec.Adjustments) != 0 {
		t.Errorf("clean run recorded adjustments: %+v", rec.Adjustments)
	}
}

// TestChallengerRun_EmitsValueNormalizedEvent covers the second half of
// the Part-2 answer: when the pipeline supplies an event sink, the
// rewrite also lands on the run-wide events stream so it is ordered
// against the llm_call_completed that produced the offending value.
func TestChallengerRun_EmitsValueNormalizedEvent(t *testing.T) {
	runDir := challengerRunFixture(t)
	rec := &captureRecorder{}
	fake := &llmtest.FakeClient{Responses: []string{
		phase1Reply("quite sure"), phase1Reply("medium"),
		phase2Reply("moderate"), phase2Reply("sort of"),
	}}
	cfg := config.Config{RunDir: runDir, AgentID: "challenger-001"}
	if err := RunWithEvents(cfg, fake, rec); err != nil {
		t.Fatalf("RunWithEvents: %v", err)
	}

	var normalized []map[string]any
	for _, e := range rec.emitted {
		b, _ := json.Marshal(e)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if m["type"] == "value_normalized" {
			normalized = append(normalized, m)
		}
	}
	if len(normalized) != 2 {
		t.Fatalf("expected 2 value_normalized events (confidence + exploitability), got %d: %+v", len(normalized), rec.emitted)
	}
	for _, m := range normalized {
		if m["from_value"] == nil || m["to_value"] == nil {
			t.Errorf("value_normalized event carries no before/after: %+v", m)
		}
		if m["case_id"] != "case-001" {
			t.Errorf("value_normalized event not attributed to the case: %+v", m)
		}
	}
}
