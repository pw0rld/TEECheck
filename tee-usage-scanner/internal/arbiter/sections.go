package arbiter

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// buildSections assembles the §7.9 / §25 clearly-separated packet
// sections: anchored ToolFacts; architecture evidence status;
// invariant verification status; Expert hypothesis; independent
// Challenger result; Verifier resolution; remaining coverage gaps;
// human-review questions. It is the single source both the JSON
// FindingItem.Sections field and the Markdown packet render from, so
// the two representations cannot drift apart.
//
// This function AGGREGATES — it does not re-derive a verdict, re-run
// a tool, or re-analyze the repo (§7.9: "不重新自由分析整个仓库"). Every
// value here already exists on pack/hypothesis/challenge/memo/caseCtx
// /independent; this is presentation, not new judgment.
func buildSections(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, caseCtx caseContext, independent artifacts.ChallengerIndependentView) artifacts.ArbiterSections {
	return artifacts.ArbiterSections{
		AnchoredToolFacts:           renderAnchoredToolFacts(caseCtx),
		ArchitectureEvidenceStatus:  renderArchitectureEvidenceStatus(caseCtx.archModel),
		InvariantVerificationStatus: renderInvariantVerificationStatus(caseCtx.invariants, memo.InvariantUpdates),
		ExpertHypothesis:            renderExpertHypothesisSection(hypothesis),
		IndependentChallengerResult: renderIndependentChallengerSection(challenge, independent),
		VerifierResolution:          renderVerifierResolutionSection(memo),
		RemainingCoverageGaps:       renderRemainingCoverageGaps(pack, memo),
		HumanReviewQuestions:        renderHumanReviewQuestions(pack, hypothesis, challenge, memo),
	}
}

func renderAnchoredToolFacts(caseCtx caseContext) []string {
	var out []string
	for _, f := range caseCtx.toolFacts {
		out = append(out, artifacts.FormatToolFact(f))
	}
	for _, ref := range caseCtx.missingToolFacts {
		out = append(out, fmt.Sprintf("(unavailable) %s", ref))
	}
	return out
}

func renderArchitectureEvidenceStatus(model *artifacts.ArchitectureModel) []string {
	if model == nil {
		return nil
	}
	var out []string
	add := func(kind, id, name string, state artifacts.EvidenceState) {
		out = append(out, fmt.Sprintf("%s:%s (%s) — %s", kind, id, state, name))
	}
	for _, e := range model.Parties {
		add("party", e.ID, e.Name, e.State)
	}
	for _, e := range model.Components {
		add("component", e.ID, e.Name, e.State)
	}
	for _, e := range model.Roles {
		add("role", e.ID, e.Name, e.State)
	}
	for _, e := range model.Assets {
		add("asset", e.ID, e.Name, e.State)
	}
	for _, e := range model.TrustZones {
		add("trust_zone", e.ID, e.Name, e.State)
	}
	for _, e := range model.Entrypoints {
		add("entrypoint", e.ID, e.Name, e.State)
	}
	for _, r := range model.Boundaries {
		add("boundary", r.ID, r.From+" -> "+r.To, r.State)
	}
	for _, r := range model.DataFlows {
		add("data_flow", r.ID, r.From+" -> "+r.To, r.State)
	}
	for _, r := range model.StateLifecycles {
		add("state_lifecycle", r.ID, r.From+" -> "+r.To, r.State)
	}
	return out
}

func renderInvariantVerificationStatus(invs []artifacts.ProjectInvariant, updates []artifacts.InvariantStatusUpdate) []string {
	updateByID := make(map[string]artifacts.InvariantStatusUpdate, len(updates))
	for _, u := range updates {
		updateByID[u.InvariantID] = u
	}
	var out []string
	for _, inv := range invs {
		line := fmt.Sprintf("%s [%s]: %s", inv.InvariantID, inv.Status, inv.Statement)
		if u, ok := updateByID[inv.InvariantID]; ok {
			line += fmt.Sprintf(" — Verifier proposes: %s -> %s (%s; NOT applied to the stored artifact, §3.5)", u.PreviousStatus, u.NewStatus, u.Reason)
		}
		out = append(out, line)
	}
	return out
}

func renderExpertHypothesisSection(hypothesis artifacts.Hypothesis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Title: %s\n", hypothesis.Title)
	fmt.Fprintf(&b, "Summary: %s\n", hypothesis.Summary)
	fmt.Fprintf(&b, "Suspected issue: %s\n", hypothesis.SuspectedIssue)
	fmt.Fprintf(&b, "Classification: %s\n", firstNonEmptyStr(hypothesis.Classification, "(unclassified)"))
	fmt.Fprintf(&b, "Confidence: %s\n", hypothesis.Confidence)
	if len(hypothesis.MissingObligations) > 0 {
		fmt.Fprintf(&b, "Missing obligations: %s\n", strings.Join(hypothesis.MissingObligations, ", "))
	}
	if len(hypothesis.AttackPremises) > 0 {
		fmt.Fprintf(&b, "Attack premises: %s\n", strings.Join(hypothesis.AttackPremises, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderIndependentChallengerSection(challenge artifacts.Challenge, independent artifacts.ChallengerIndependentView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Phase-1 issue_present (formed without the Expert hypothesis): %v\n", independent.IssuePresent)
	if independent.Reasoning != "" {
		fmt.Fprintf(&b, "Phase-1 reasoning: %s\n", independent.Reasoning)
	}
	if len(independent.DefensesConsidered) > 0 {
		fmt.Fprintf(&b, "Defenses considered: %s\n", strings.Join(independent.DefensesConsidered, "; "))
	}
	fmt.Fprintf(&b, "Key differences vs. Expert hypothesis: %s\n", strings.Join(orNone(challenge.KeyDifferences), "; "))
	fmt.Fprintf(&b, "Exploitability: %s | Reviewer stance: %s\n", artifacts.FormatRating(challenge.Exploitability), challenge.ReviewerStance)
	return strings.TrimRight(b.String(), "\n")
}

func renderVerifierResolutionSection(memo artifacts.VerificationMemo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Status: %s\n", memo.Status)
	if len(memo.ConfirmedFacts) > 0 {
		fmt.Fprintf(&b, "Confirmed facts: %s\n", strings.Join(memo.ConfirmedFacts, "; "))
	}
	if len(memo.Contradictions) > 0 {
		fmt.Fprintf(&b, "Contradictions: %s\n", strings.Join(memo.Contradictions, "; "))
	}
	if len(memo.EvidenceDistinctions) > 0 {
		var parts []string
		for _, d := range memo.EvidenceDistinctions {
			parts = append(parts, fmt.Sprintf("[%s] %s (%s)", d.Outcome, d.Claim, d.Note))
		}
		fmt.Fprintf(&b, "Evidence distinctions (not-found vs proven-absent): %s\n", strings.Join(parts, "; "))
	}
	if len(memo.ArchitectureChecks) > 0 {
		fmt.Fprintf(&b, "Architecture statements consulted: %s\n", strings.Join(memo.ArchitectureChecks, "; "))
	}
	// InvariantChecks is the documented twin of ArchitectureChecks
	// (types.go: "short text notes on the architecture statements /
	// invariants the Verifier consulted"), so it belongs in the same
	// "what did the Verifier's judgment lean on" section rather than
	// in the gaps list — the entries carry each invariant's status
	// verbatim, including satisfied ones.
	if len(memo.InvariantChecks) > 0 {
		fmt.Fprintf(&b, "Invariant verification plans consulted: %s\n", strings.Join(memo.InvariantChecks, "; "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// verifierGapPrefix marks the entries the Verifier left open, so a
// reader can tell them apart from the Case Pack's pre-agent gaps.
const verifierGapPrefix = "verifier: "

// renderRemainingCoverageGaps answers "what is still uncovered now
// that the Expert, Challenger and Verifier have run". The Case Pack
// contributes what was open before they started; the memo contributes
// what the Verifier could not close.
//
// Only memo fields whose semantics are "still outstanding" are folded
// in. Anything the Verifier settled stays out: ConfirmedFacts /
// ConfirmedCitedFacts are confirmations, Contradictions /
// ContradictedCitedFacts are reached conclusions, proven_absent
// distinctions are verified absences, and valid expert citations
// still anchor. ChecksRun and Notes narrate the work rather than name
// a gap; InvariantUpdates, ArchitectureChecks and InvariantChecks are
// each already rendered, with more context, by another section.
func renderRemainingCoverageGaps(pack artifacts.CasePack, memo artifacts.VerificationMemo) []string {
	var out []string
	out = append(out, pack.CoverageGaps...)
	for _, link := range pack.MissingLinks {
		out = append(out, "missing_link: "+link)
	}
	for _, req := range pack.RequiredEvidence {
		out = append(out, "still-required evidence: "+req)
	}

	addVerifier := func(format string, args ...any) {
		out = append(out, verifierGapPrefix+fmt.Sprintf(format, args...))
	}

	// An inconclusive memo is itself the top-level open item: the
	// dispute the three agents were run to settle is not settled.
	if memo.Status == "inconclusive" {
		out = append(out, verifierGapPrefix+"dispute still inconclusive after verification")
	}
	// not_found means the tool layer was asked and saw nothing, but
	// nothing ran an exhaustive check — the property may still hold,
	// so the claim is uncovered rather than resolved (§7.8).
	for _, d := range memo.EvidenceDistinctions {
		if d.Outcome != artifacts.EvidenceNotFound {
			continue
		}
		line := fmt.Sprintf("not found, NOT proven absent: %s", d.Claim)
		if d.Note != "" {
			line += fmt.Sprintf(" (%s)", d.Note)
		}
		addVerifier("%s", line)
	}
	// CandidateFacts are static-tool hits the Verifier did not
	// independently confirm; by contract they must not carry the
	// verdict on their own, which makes each one an open item.
	for _, f := range memo.CandidateFacts {
		addVerifier("unconfirmed candidate fact: %s", f)
	}
	// An expert claim whose citations no longer anchor (stale /
	// unanchored / unresolved) has no live evidence behind it after
	// verification. Valid ones are skipped.
	for _, v := range memo.ExpertCitationValidation {
		if v.Status == citations.StatusValid {
			continue
		}
		line := fmt.Sprintf("expert claim not backed by live citations [%s]: %s", v.Status, v.FactText)
		if v.Reason != "" {
			line += fmt.Sprintf(" (%s)", v.Reason)
		}
		addVerifier("%s", line)
	}

	return out
}

func renderHumanReviewQuestions(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo) []string {
	qs := []string{
		"Does the visible code really represent the trust decision point?",
		"Is wrapper or helper context likely to change this verdict?",
		"If the issue is real, what concrete security property fails?",
	}
	qs = append(qs, challenge.RemainingQuestions...)
	qs = append(qs, pack.OpenQuestions...)
	return dedupeStrings(qs)
}

func orNone(values []string) []string {
	if len(values) == 0 {
		return []string{"(none)"}
	}
	return values
}

func firstNonEmptyStr(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// busEvidence renders what a bus agent is allowed to reason from. It has no
// file access and no tools, so this is the whole of its world; agentbus
// refuses a query that arrives without it.
func busEvidence(pack artifacts.CasePack, caseCtx caseContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Case %s\ntarget files: %s\n", pack.CaseID, strings.Join(pack.TargetFiles, ", "))
	if len(pack.TargetSymbols) > 0 {
		fmt.Fprintf(&b, "target symbols: %s\n", strings.Join(pack.TargetSymbols, ", "))
	}
	b.WriteString("\nToolFacts (immutable):\n")
	if facts := renderAnchoredToolFacts(caseCtx); len(facts) > 0 {
		b.WriteString(strings.Join(facts, "\n"))
	} else {
		b.WriteString("(none)")
	}
	if len(pack.Snippets) > 0 {
		b.WriteString("\n\nSource snippets:\n")
		for _, sn := range pack.Snippets {
			fmt.Fprintf(&b, "--- %s:%d-%d\n%s\n", sn.Path, sn.StartLine, sn.EndLine, sn.Content)
		}
	}
	return b.String()
}
