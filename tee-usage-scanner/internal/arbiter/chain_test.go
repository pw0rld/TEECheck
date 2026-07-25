package arbiter

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// ─── attackChainComplete ──────────────────────────────────────────────

func TestAttackChainComplete_AllSignalsClean(t *testing.T) {
	pack := artifacts.CasePack{}
	hyp := artifacts.Hypothesis{NeedsVerification: false}
	memo := artifacts.VerificationMemo{Status: "corroborated"}
	if !attackChainComplete(pack, hyp, memo) {
		t.Error("expected complete chain: no missing links, no needs_verification, corroborated, no contradictions")
	}
}

func TestAttackChainComplete_FalseWhenMissingLinks(t *testing.T) {
	pack := artifacts.CasePack{MissingLinks: []string{"loader role unresolved"}}
	memo := artifacts.VerificationMemo{Status: "corroborated"}
	if attackChainComplete(pack, artifacts.Hypothesis{}, memo) {
		t.Error("expected incomplete chain when MissingLinks is non-empty")
	}
}

func TestAttackChainComplete_FalseWhenNeedsVerification(t *testing.T) {
	hyp := artifacts.Hypothesis{NeedsVerification: true}
	memo := artifacts.VerificationMemo{Status: "corroborated"}
	if attackChainComplete(artifacts.CasePack{}, hyp, memo) {
		t.Error("expected incomplete chain when Expert flagged NeedsVerification")
	}
}

func TestAttackChainComplete_FalseWhenNotCorroborated(t *testing.T) {
	for _, status := range []string{"contested", "inconclusive", ""} {
		memo := artifacts.VerificationMemo{Status: status}
		if attackChainComplete(artifacts.CasePack{}, artifacts.Hypothesis{}, memo) {
			t.Errorf("expected incomplete chain for verifier status %q", status)
		}
	}
}

func TestAttackChainComplete_FalseWhenContradictions(t *testing.T) {
	memo := artifacts.VerificationMemo{Status: "corroborated", Contradictions: []string{"x"}}
	if attackChainComplete(artifacts.CasePack{}, artifacts.Hypothesis{}, memo) {
		t.Error("expected incomplete chain when Contradictions is non-empty")
	}
	memo2 := artifacts.VerificationMemo{Status: "corroborated", UntypedContradictions: []string{"y"}}
	if attackChainComplete(artifacts.CasePack{}, artifacts.Hypothesis{}, memo2) {
		t.Error("expected incomplete chain when UntypedContradictions is non-empty")
	}
}

// ─── §25 acceptance: no "confirmed vulnerability" wording without a complete chain ───

func TestSanitizeFindingItem_DowngradesConfirmedStatusWhenIncomplete(t *testing.T) {
	item := artifacts.FindingItem{Status: "confirmed_candidate", Summary: "This is a confirmed vulnerability in the loader."}
	got := sanitizeFindingItem(item, false)
	if got.Status == "confirmed_candidate" {
		t.Errorf("Status not downgraded: %q", got.Status)
	}
	if strings.Contains(strings.ToLower(got.Summary), "confirmed vulnerability") {
		t.Errorf("Summary still contains the forbidden phrase: %q", got.Summary)
	}
}

func TestSanitizeFindingItem_ScrubsEvidenceToo(t *testing.T) {
	item := artifacts.FindingItem{
		Status:   "likely_issue",
		Evidence: []string{"tool found a Confirmed Vulnerability at line 42", "unrelated evidence"},
	}
	got := sanitizeFindingItem(item, false)
	for _, e := range got.Evidence {
		if strings.Contains(strings.ToLower(e), "confirmed vulnerability") {
			t.Errorf("evidence still contains the forbidden phrase: %q", e)
		}
	}
	if !strings.Contains(got.Evidence[1], "unrelated evidence") {
		t.Errorf("unrelated evidence entry corrupted: %q", got.Evidence[1])
	}
}

func TestSanitizeFindingItem_NoOpWhenChainComplete(t *testing.T) {
	item := artifacts.FindingItem{Status: "confirmed_candidate", Summary: "confirmed vulnerability, chain complete"}
	got := sanitizeFindingItem(item, true)
	if got.Status != "confirmed_candidate" {
		t.Errorf("complete chain should not be downgraded, got %q", got.Status)
	}
	if !strings.Contains(got.Summary, "confirmed vulnerability") {
		t.Error("complete chain should not have its summary scrubbed")
	}
}

func TestScrubConfirmedWording_CaseInsensitiveAllOccurrences(t *testing.T) {
	in := "A CONFIRMED VULNERABILITY here, and another confirmed vulnerability there."
	out := scrubConfirmedWording(in)
	if strings.Contains(strings.ToLower(out), "confirmed vulnerability") {
		t.Errorf("not all occurrences scrubbed: %q", out)
	}
	if !strings.Contains(out, "here, and another") {
		t.Errorf("surrounding text corrupted: %q", out)
	}
}

// ─── End-to-end: the §25 gate scrubs confirmed-vulnerability wording ───
// out of the LLM arbiter's output when the chain is incomplete, even
// when the model ignores the CRITICAL RULE and emits it anyway. ──────

func TestArbitrateLLM_NoConfirmedWordingWithoutCompleteChain(t *testing.T) {
	pack := artifacts.CasePack{CaseID: "case-001", Category: "rollback", MissingLinks: []string{"rollback DB role unresolved"}}
	hyp := artifacts.Hypothesis{CaseID: "case-001", Confidence: "high", SuspectedIssue: "possible issue in rollback check"}
	challenge := artifacts.Challenge{CaseID: "case-001"}
	memo := artifacts.VerificationMemo{CaseID: "case-001", Status: "corroborated"}

	// The model defies the prompt: it returns "confirmed_candidate" and
	// the forbidden phrase in both structured and free-text fields. The
	// mechanical §25 gate must still scrub all of it because the chain
	// is incomplete (MissingLinks present).
	client := &llmtest.FakeClient{Responses: []string{`{
		"status": "confirmed_candidate",
		"severity": "high",
		"confidence": "high",
		"summary": "This is a confirmed vulnerability in the rollback check",
		"evidence": ["evidence of a confirmed vulnerability"],
		"review_packet_markdown": "# Packet\n\nThis is a confirmed vulnerability.",
		"queries": []
	}`}}
	bus := agentbus.New(0)

	item, packet, err := arbitrateLLM(context.Background(), client, bus, pack, hyp, challenge, memo, caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0)
	if err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}

	if isConfirmedStatus(item.Status) {
		t.Errorf("Status=%q should not be a confirmed* status (MissingLinks present)", item.Status)
	}
	if strings.Contains(strings.ToLower(item.Summary), confirmedVulnerabilityPhrase) {
		t.Errorf("Summary contains forbidden phrase: %q", item.Summary)
	}
	if strings.Contains(strings.ToLower(packet), confirmedVulnerabilityPhrase) {
		t.Errorf("packet contains forbidden phrase:\n%s", packet)
	}
}

func TestArbitrateLLM_ConfirmedCandidateAllowedWithCompleteChain(t *testing.T) {
	pack := artifacts.CasePack{CaseID: "case-001", Category: "rollback"}
	hyp := artifacts.Hypothesis{CaseID: "case-001", Confidence: "high", NeedsVerification: false}
	challenge := artifacts.Challenge{CaseID: "case-001"}
	memo := artifacts.VerificationMemo{CaseID: "case-001", Status: "corroborated"}

	client := &llmtest.FakeClient{Responses: []string{`{
		"status": "confirmed_candidate",
		"severity": "high",
		"confidence": "high",
		"summary": "clear finding",
		"evidence": [],
		"review_packet_markdown": "# Packet",
		"queries": []
	}`}}
	bus := agentbus.New(0)

	item, _, err := arbitrateLLM(context.Background(), client, bus, pack, hyp, challenge, memo, caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0)
	if err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}
	if item.Status != "confirmed_candidate" {
		t.Errorf("Status=%q, want confirmed_candidate when the chain is actually complete", item.Status)
	}
}
