package arbiter

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// wantVerifierPrefix is spelled out literally so renaming the
// production constant cannot silently keep this test green.
const wantVerifierPrefix = "verifier: "

// gapPack is the pre-agent half of the section: everything the Case
// Pack already knew before the Expert / Challenger / Verifier ran.
func gapPack() artifacts.CasePack {
	return artifacts.CasePack{
		CaseID:           "case-001",
		CoverageGaps:     []string{"only 2 of 5 call sites reviewed"},
		MissingLinks:     []string{"loader role"},
		RequiredEvidence: []string{"reverse trace to authority"},
	}
}

func hasPrefixed(lines []string, prefix, needle string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) && strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func containsAny(lines []string, needle string) bool {
	for _, l := range lines {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

// TestRemainingCoverageGaps_IncludesVerifierDiscoveredGaps is the core
// of defect 2: the section is named for what is still uncovered AFTER
// verification, so what the Verifier left open has to appear in it.
func TestRemainingCoverageGaps_IncludesVerifierDiscoveredGaps(t *testing.T) {
	memo := artifacts.VerificationMemo{
		Status: "inconclusive",
		EvidenceDistinctions: []artifacts.EvidenceDistinctionNote{
			{Claim: "no freshness check on the quote", Outcome: artifacts.EvidenceNotFound, Note: "grep only, not exhaustive"},
		},
		CandidateFacts: []string{"semgrep flagged verify_quote without nonce"},
		ExpertCitationValidation: []citations.CitationValidation{
			{FactText: "nonce is never compared", Status: citations.StatusStale, Reason: "sha mismatch at verify.rs"},
		},
	}

	got := renderRemainingCoverageGaps(gapPack(), memo)

	for _, want := range []string{
		"no freshness check on the quote",
		"semgrep flagged verify_quote without nonce",
		"nonce is never compared",
		"inconclusive",
	} {
		if !hasPrefixed(got, wantVerifierPrefix, want) {
			t.Errorf("missing verifier-origin gap %q in:\n%v", want, got)
		}
	}
}

// TestRemainingCoverageGaps_DistinguishesOrigins: a human reading the
// section must be able to tell "open from the start" from "the
// Verifier found this still open".
func TestRemainingCoverageGaps_DistinguishesOrigins(t *testing.T) {
	memo := artifacts.VerificationMemo{
		CandidateFacts: []string{"unconfirmed tool hit"},
	}

	got := renderRemainingCoverageGaps(gapPack(), memo)

	packDerived := map[string]bool{
		"only 2 of 5 call sites reviewed":                     true,
		"missing_link: loader role":                           true,
		"still-required evidence: reverse trace to authority": true,
	}
	var sawPack, sawVerifier int
	for _, line := range got {
		switch {
		case packDerived[line]:
			sawPack++
		case strings.HasPrefix(line, wantVerifierPrefix):
			sawVerifier++
		default:
			t.Errorf("line %q is neither a pack-derived gap nor prefixed %q", line, wantVerifierPrefix)
		}
	}
	if sawPack != 3 {
		t.Errorf("expected the 3 pack-derived gaps to keep their existing form, saw %d in:\n%v", sawPack, got)
	}
	if sawVerifier != 1 {
		t.Errorf("expected 1 verifier-origin gap, saw %d in:\n%v", sawVerifier, got)
	}
}

// TestRemainingCoverageGaps_ConfirmedFactIsNotAGap: everything the
// Verifier settled must stay out. proven_absent is a resolved
// conclusion, not an uncovered area; so are confirmed facts,
// contradictions and valid expert citations.
func TestRemainingCoverageGaps_ConfirmedFactIsNotAGap(t *testing.T) {
	memo := artifacts.VerificationMemo{
		Status:         "corroborated",
		ConfirmedFacts: []string{"CONFIRMED-FACT: signature is checked in verify()"},
		ConfirmedCitedFacts: []citations.CitedFact{
			{Text: "CITED-CONFIRMED: nonce compared at line 42"},
		},
		Contradictions: []string{"CONTRADICTION: expert misread the wrapper"},
		ContradictedCitedFacts: []citations.CitedFact{
			{Text: "CITED-CONTRADICTION: the check exists"},
		},
		EvidenceDistinctions: []artifacts.EvidenceDistinctionNote{
			{Claim: "PROVEN-ABSENT-CLAIM", Outcome: artifacts.EvidenceProvenAbsent, Note: "exhaustive fact-layer query"},
		},
		ExpertCitationValidation: []citations.CitationValidation{
			{FactText: "VALID-CITATION", Status: citations.StatusValid},
		},
		ChecksRun:          []string{"CHECKS-RUN: ran semgrep"},
		Notes:              []string{"NOTE: narration"},
		ArchitectureChecks: []string{"ARCH-CHECK: boundary is inferred"},
	}

	got := renderRemainingCoverageGaps(gapPack(), memo)

	for _, unwanted := range []string{
		"CONFIRMED-FACT", "CITED-CONFIRMED",
		"CONTRADICTION", "CITED-CONTRADICTION",
		"PROVEN-ABSENT-CLAIM", "VALID-CITATION",
		"CHECKS-RUN", "NOTE:", "ARCH-CHECK",
	} {
		if containsAny(got, unwanted) {
			t.Errorf("resolved/irrelevant memo content %q leaked into remaining gaps:\n%v", unwanted, got)
		}
	}
}

// TestRemainingCoverageGaps_EmptyMemoAddsNoNoise: a memo with nothing
// outstanding must leave the section exactly as the Case Pack had it.
func TestRemainingCoverageGaps_EmptyMemoAddsNoNoise(t *testing.T) {
	got := renderRemainingCoverageGaps(gapPack(), artifacts.VerificationMemo{Status: "corroborated"})
	if len(got) != 3 {
		t.Fatalf("expected exactly the 3 pack-derived gaps, got %d:\n%v", len(got), got)
	}
	for _, line := range got {
		if strings.HasPrefix(line, wantVerifierPrefix) {
			t.Errorf("empty memo produced a verifier-origin line %q", line)
		}
	}
}

// TestVerifierResolution_ShowsInvariantChecks: InvariantChecks is the
// documented twin of ArchitectureChecks ("which project-understanding
// facts the Verifier's judgment depended on") and had no reader.
func TestVerifierResolution_ShowsInvariantChecks(t *testing.T) {
	memo := artifacts.VerificationMemo{
		Status:             "contested",
		ArchitectureChecks: []string{"boundary:tee-ta-001 is inferred, not observed"},
		InvariantChecks:    []string{"inv-1 [proposed]: grep for version check"},
	}
	got := renderVerifierResolutionSection(memo)
	if !strings.Contains(got, "inv-1 [proposed]: grep for version check") {
		t.Errorf("VerifierResolution dropped memo.InvariantChecks:\n%s", got)
	}
	if !strings.Contains(got, "boundary:tee-ta-001") {
		t.Errorf("VerifierResolution dropped memo.ArchitectureChecks:\n%s", got)
	}
}
