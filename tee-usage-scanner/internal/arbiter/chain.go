package arbiter

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// attackChainComplete is the §25 acceptance mechanical gate: "无完整
// 攻击链时不能使用 confirmed vulnerability 表述" (with no complete attack
// chain, output must not use "confirmed vulnerability" wording). This
// function is the single source of truth both arbitrate() (heuristic)
// and arbitrateLLM() consult before EVER assigning a status
// containing "confirmed" or before letting free text through
// unsanitized — the rule lives in code, not only in a prompt
// instruction an LLM could ignore.
//
// A chain counts as complete when ALL of:
//   - the Investigator left no MissingLinks outstanding (no unfilled
//     role the attack depends on)
//   - the Expert did not itself flag NeedsVerification
//   - the Verifier's status is "corroborated" (not merely
//     "inconclusive" or "contested")
//   - the Verifier recorded no Contradictions (validated or untyped)
//
// This is deliberately conservative: any one of these signals absent
// evidence, an internal doubt, or an unresolved dispute is enough to
// withhold "confirmed" wording.
func attackChainComplete(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, memo artifacts.VerificationMemo) bool {
	if len(pack.MissingLinks) > 0 {
		return false
	}
	if hypothesis.NeedsVerification {
		return false
	}
	if memo.Status != "corroborated" {
		return false
	}
	if len(memo.Contradictions) > 0 || len(memo.UntypedContradictions) > 0 {
		return false
	}
	return true
}

// confirmedStatusPrefix identifies any FindingItem.Status value this
// package (or an LLM speaking through arbitrateLLM) might produce
// that asserts confirmation, so sanitizeFindingItem can downgrade it
// mechanically rather than relying on the LLM to have honored the
// prompt's instruction.
func isConfirmedStatus(status string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(status)), "confirmed")
}

// sanitizeFindingItem enforces the gate on an already-built
// FindingItem: if the attack chain is not complete, any "confirmed*"
// status is downgraded to "likely_issue", and any occurrence of the
// phrase "confirmed vulnerability" (case-insensitive) in Summary or
// Evidence is rewritten to make the incompleteness explicit rather
// than silently dropped. Applied unconditionally at the end of both
// arbitrate() and arbitrateLLM() — an LLM that ignores every prompt
// instruction and writes "confirmed vulnerability" anyway still gets
// caught here.
func sanitizeFindingItem(item artifacts.FindingItem, complete bool) artifacts.FindingItem {
	if complete {
		return item
	}
	if isConfirmedStatus(item.Status) {
		item.Status = "likely_issue"
	}
	item.Summary = scrubConfirmedWording(item.Summary)
	for i, e := range item.Evidence {
		item.Evidence[i] = scrubConfirmedWording(e)
	}
	return item
}

const confirmedVulnerabilityPhrase = "confirmed vulnerability"

// scrubConfirmedWording case-insensitively replaces the phrase
// "confirmed vulnerability" with an explicit statement of
// incompleteness, preserving the rest of the sentence rather than
// deleting it outright.
func scrubConfirmedWording(s string) string {
	lower := strings.ToLower(s)
	idx := strings.Index(lower, confirmedVulnerabilityPhrase)
	if idx < 0 {
		return s
	}
	replacement := "unconfirmed (attack chain incomplete) issue"
	var b strings.Builder
	rest := s
	for {
		lowerRest := strings.ToLower(rest)
		i := strings.Index(lowerRest, confirmedVulnerabilityPhrase)
		if i < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		b.WriteString(replacement)
		rest = rest[i+len(confirmedVulnerabilityPhrase):]
	}
	return b.String()
}

// chainCompletenessNote renders a short, human-readable explanation
// for why "confirmed" wording was or was not available, so the
// packet's Arbiter Status line is self-explaining rather than
// requiring the reader to re-derive the gate.
func chainCompletenessNote(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, memo artifacts.VerificationMemo, complete bool) string {
	if complete {
		return "attack chain complete: no missing links, Expert did not flag needs_verification, Verifier status is corroborated with no contradictions"
	}
	var reasons []string
	if len(pack.MissingLinks) > 0 {
		reasons = append(reasons, fmt.Sprintf("missing_links outstanding: %s", strings.Join(pack.MissingLinks, ", ")))
	}
	if hypothesis.NeedsVerification {
		reasons = append(reasons, "Expert flagged needs_verification")
	}
	if memo.Status != "corroborated" {
		reasons = append(reasons, fmt.Sprintf("Verifier status is %q, not corroborated", memo.Status))
	}
	if len(memo.Contradictions) > 0 || len(memo.UntypedContradictions) > 0 {
		reasons = append(reasons, "Verifier recorded contradictions")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "unknown gap")
	}
	return "attack chain incomplete (" + strings.Join(reasons, "; ") + ") — confirmed-vulnerability wording withheld"
}
