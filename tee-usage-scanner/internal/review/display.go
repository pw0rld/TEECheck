package review

import (
	"fmt"
	"io"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// DisplayPacketSummary renders a finding for the human reviewer.
// Phase 1: instead of dumping the LLM packet markdown verbatim, the
// display is structured into four explicit sections so the reviewer
// can tell at a glance which evidence is anchored vs background:
//
//   - Verdict summary  (arbiter status / severity / confidence / files)
//   - Anchored evidence  (Hypothesis.SupportingFacts +
//     memo.ConfirmedFacts + citation refs)
//   - Unanchored context (UntypedFacts + verifier untyped fields,
//     all tagged [unanchored ...])
//   - Verifier judgment  (status + Contradictions, citation-aware)
//
// The full LLM packet is still printed at the end as a reference
// when packetText is non-empty — useful when the structured view
// loses prose context the reviewer needs.
func DisplayPacketSummary(w io.Writer, idx, total int, finding artifacts.FindingItem, packetText string) {
	bar := strings.Repeat("━", 60)
	fmt.Fprintf(w, "\n%s\n", bar)
	fmt.Fprintf(w, "Case %d/%d: %s\n", idx+1, total, finding.FindingID)
	fmt.Fprintf(w, "%s\n\n", bar)

	displayVerdictSummary(w, finding)
	if packetText != "" {
		fmt.Fprintf(w, "\n%s LLM Review Packet (reference) %s\n%s\n",
			strings.Repeat("─", 14),
			strings.Repeat("─", 14),
			packetText)
	}
	fmt.Fprintf(w, "\n%s\n", bar)
}

// DisplayFindingDetail renders the structured review surface using
// the case's hypothesis + memo when available. Phase 1 uses this
// before the prompt loop in `teecheck review` so the reviewer can
// label without round-tripping to other files.
//
// hyp and memo may be zero-valued if loading them failed; the
// renderer handles that by skipping the corresponding sections.
func DisplayFindingDetail(w io.Writer, finding artifacts.FindingItem, hyp artifacts.Hypothesis, memo artifacts.VerificationMemo) {
	displayAnchoredEvidence(w, hyp, memo)
	displayUnanchoredContext(w, hyp, memo)
	displayVerifierJudgment(w, memo)
	displayCitationRefs(w, hyp, memo)
}

func displayVerdictSummary(w io.Writer, f artifacts.FindingItem) {
	fmt.Fprintln(w, "VERDICT SUMMARY")
	fmt.Fprintf(w, "  Arbiter status:   %s\n", f.Status)
	fmt.Fprintf(w, "  Severity:         %s\n", f.Severity)
	fmt.Fprintf(w, "  Confidence:       %s\n", f.Confidence)
	if len(f.Files) > 0 {
		fmt.Fprintf(w, "  Files:            %s\n", strings.Join(f.Files, ", "))
	}
	if f.Summary != "" {
		fmt.Fprintf(w, "  Summary:          %s\n", f.Summary)
	}
	fmt.Fprintln(w)
}

func displayAnchoredEvidence(w io.Writer, hyp artifacts.Hypothesis, memo artifacts.VerificationMemo) {
	fmt.Fprintln(w, "ANCHORED EVIDENCE (citation-validated)")
	any := false
	if len(hyp.CitedFacts) > 0 {
		fmt.Fprintln(w, "  Expert cited facts:")
		for i, f := range hyp.CitedFacts {
			if !f.HasValidCitation() {
				continue
			}
			fmt.Fprintf(w, "    %d. %s\n", i+1, f.Text)
			for _, c := range f.Cited {
				if !c.Resolved() {
					continue
				}
				fmt.Fprintf(w, "         - %s:%d-%d\n", c.File, c.StartLine, c.EndLine)
			}
			any = true
		}
	}
	if len(memo.ConfirmedCitedFacts) > 0 {
		fmt.Fprintln(w, "  Verifier confirmed facts:")
		for i, f := range memo.ConfirmedCitedFacts {
			if !f.HasValidCitation() {
				continue
			}
			fmt.Fprintf(w, "    %d. %s\n", i+1, f.Text)
			for _, c := range f.Cited {
				if !c.Resolved() {
					continue
				}
				fmt.Fprintf(w, "         - %s:%d-%d\n", c.File, c.StartLine, c.EndLine)
			}
			any = true
		}
	}
	if !any {
		fmt.Fprintln(w, "  (none)")
	}
	fmt.Fprintln(w)
}

func displayUnanchoredContext(w io.Writer, hyp artifacts.Hypothesis, memo artifacts.VerificationMemo) {
	fmt.Fprintln(w, "UNANCHORED CONTEXT (background; not citation-validated)")
	any := false
	if len(hyp.UntypedFacts) > 0 {
		fmt.Fprintln(w, "  Expert untyped facts (tool hits / legacy text):")
		for _, u := range hyp.UntypedFacts {
			fmt.Fprintf(w, "    - [unanchored] %s\n", u)
			any = true
		}
	}
	if len(memo.UntypedConfirmedFacts) > 0 {
		fmt.Fprintln(w, "  Verifier untyped confirmations:")
		for _, u := range memo.UntypedConfirmedFacts {
			fmt.Fprintf(w, "    - [unanchored verifier confirm] %s\n", u)
			any = true
		}
	}
	if len(memo.UntypedContradictions) > 0 {
		fmt.Fprintln(w, "  Verifier untyped contradictions:")
		for _, u := range memo.UntypedContradictions {
			fmt.Fprintf(w, "    - [unanchored verifier contradict] %s\n", u)
			any = true
		}
	}
	// CitedFacts whose citations all failed are also untyped from
	// the reviewer's perspective — show them here.
	for _, f := range hyp.CitedFacts {
		if f.HasValidCitation() {
			continue
		}
		fmt.Fprintf(w, "    - [unanchored — failed resolve] %s\n", f.Text)
		any = true
	}
	if !any {
		fmt.Fprintln(w, "  (none)")
	}
	fmt.Fprintln(w)
}

func displayVerifierJudgment(w io.Writer, memo artifacts.VerificationMemo) {
	fmt.Fprintln(w, "VERIFIER JUDGMENT")
	fmt.Fprintf(w, "  Status: %s\n", memo.Status)
	if len(memo.ContradictedCitedFacts) > 0 {
		fmt.Fprintln(w, "  Contradictions (anchored):")
		for i, f := range memo.ContradictedCitedFacts {
			fmt.Fprintf(w, "    %d. %s\n", i+1, f.Text)
			for _, c := range f.Cited {
				if !c.Resolved() {
					continue
				}
				fmt.Fprintf(w, "         - %s:%d-%d\n", c.File, c.StartLine, c.EndLine)
			}
		}
	}
	if len(memo.ExpertCitationValidation) > 0 {
		fmt.Fprintln(w, "  Expert citation validation:")
		for _, v := range memo.ExpertCitationValidation {
			fmt.Fprintf(w, "    [%s] %s\n", v.Status, truncate(v.FactText, 80))
		}
	}
	fmt.Fprintln(w)
}

func displayCitationRefs(w io.Writer, hyp artifacts.Hypothesis, memo artifacts.VerificationMemo) {
	fmt.Fprintln(w, "CODE REFERENCES (file:line — sha256 — source)")
	any := false
	for _, c := range hyp.Cited {
		any = true
		writeCiteRef(w, c, "expert")
	}
	for _, c := range memo.Cited {
		any = true
		writeCiteRef(w, c, "verifier")
	}
	if !any {
		fmt.Fprintln(w, "  (none — finding has no resolved citations)")
	}
	fmt.Fprintln(w)
}

func writeCiteRef(w io.Writer, c citations.CitedBytes, source string) {
	short := c.SHA256
	if len(short) > 12 {
		short = short[:12]
	}
	fmt.Fprintf(w, "  - %s:%d-%d  sha:%s  (%s)\n", c.File, c.StartLine, c.EndLine, short, source)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
