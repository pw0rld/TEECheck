package challenger

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// computeKeyDifferences is the point of the two-phase design (§25
// acceptance: "vulnerable/fixed 两个 variant 的 Challenger 能识别关键差异").
// It compares the phase-1 independent verdict — formed without the
// Expert's hypothesis — against the Expert's hypothesis, and names
// where they actually disagree rather than restating both views
// side by side and leaving the reader to spot the gap.
//
// The Expert's role (§7.6) is to always construct an attack
// hypothesis for a case the Investigator selected — CasePack
// selection already implies the Expert will propose something. So
// the comparison that matters is not "did both sides agree a
// hypothesis was written" (trivially yes) but "did phase 1, informed
// only by the case's own evidence, independently find the same
// signal". A vulnerable case's independent view should agree; a
// fixed/defended case's independent view should not.
func computeKeyDifferences(hypothesis artifacts.Hypothesis, independent artifacts.ChallengerIndependentView) []string {
	var diffs []string

	if !independent.IssuePresent {
		diffs = append(diffs, fmt.Sprintf(
			"Independent phase-1 review (formed without the Expert's hypothesis) found NO supporting issue signal, contradicting the Expert's %s-confidence hypothesis %q. Independent reasoning: %s",
			hypothesis.Confidence, hypothesis.SuspectedIssue, independent.Reasoning))
	}

	if independent.IssuePresent && len(independent.DefensesConsidered) > 0 {
		diffs = append(diffs, fmt.Sprintf(
			"Independent review flagged the issue but also found candidate defenses the Expert hypothesis does not address: %s",
			strings.Join(independent.DefensesConsidered, "; ")))
	}

	if independent.IssuePresent && len(hypothesis.MissingObligations) == 0 {
		diffs = append(diffs, "Independent review flagged a concern, but the Expert hypothesis names no missing_obligations to anchor it to")
	}

	if len(diffs) == 0 {
		diffs = append(diffs, "Independent phase-1 review and the Expert hypothesis agree that an issue signal is present; no disagreement to report")
	}
	return diffs
}
