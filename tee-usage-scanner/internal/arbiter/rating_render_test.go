package arbiter

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// A Challenger that produced no usable exploitability rating must say
// so wherever a human or the Arbiter model reads it. Printing a bare
// token, or a blank, is how the 2026-07-28 "synthetic echo" defect went
// unnoticed for four days: the packet showed a value that read like a
// verdict and nothing marked it as manufactured.
func TestReviewPacketAndSection_MakeUnratedLegible(t *testing.T) {
	challenge := artifacts.Challenge{
		CaseID:         "case-001",
		Exploitability: artifacts.RatingUnrated,
		ReviewerStance: "challenge_required",
	}
	independent := artifacts.ChallengerIndependentView{CaseID: "case-001", Confidence: artifacts.RatingUnrated}

	packet := buildPacket(artifacts.CasePack{CaseID: "case-001"}, artifacts.Hypothesis{},
		challenge, artifacts.VerificationMemo{}, artifacts.FindingItem{}, artifacts.ArbiterSections{})
	if !strings.Contains(packet, "Exploitability: "+artifacts.RatingUnrated+" (") {
		t.Errorf("human review packet does not spell out the unrated exploitability:\n%s", packet)
	}
	if !strings.Contains(packet, "missing data") {
		t.Errorf("human review packet does not tell the reader this is missing data:\n%s", packet)
	}

	section := renderIndependentChallengerSection(challenge, independent)
	if !strings.Contains(section, artifacts.RatingUnrated+" (") || !strings.Contains(section, "missing data") {
		t.Errorf("independent-challenger section does not spell out the unrated exploitability:\n%s", section)
	}
}

// A legal rating must still render exactly as the Challenger set it.
func TestReviewPacket_LegalExploitabilityRendersVerbatim(t *testing.T) {
	packet := buildPacket(artifacts.CasePack{CaseID: "case-001"}, artifacts.Hypothesis{},
		artifacts.Challenge{Exploitability: "proven"}, artifacts.VerificationMemo{},
		artifacts.FindingItem{}, artifacts.ArbiterSections{})
	if !strings.Contains(packet, "- Exploitability: proven\n") {
		t.Errorf("legal exploitability did not render verbatim:\n%s", packet)
	}
}
