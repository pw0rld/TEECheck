package review

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// PromptVerdict prompts for the Phase 1 verdict vocabulary:
//   t/true_positive, f/false_positive, n/needs_more_context,
//   s/skip, q/quit
// Returns one of artifacts.Verdict* constants, or the special
// sentinel "quit" to stop the review session entirely.
func PromptVerdict(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Verdict? [t]rue positive / [f]alse positive / [n]eeds more context / [s]kip / [q]uit: ")
	if !r.Scan() {
		return "quit"
	}
	switch strings.ToLower(strings.TrimSpace(r.Text())) {
	case "t", "tp", "true_positive", "true positive":
		return artifacts.VerdictTruePositive
	case "f", "fp", "false_positive", "false positive":
		return artifacts.VerdictFalsePositive
	case "n", "nmc", "needs_more_context", "needs more context":
		return artifacts.VerdictNeedsMoreContext
	case "s", "skip":
		return artifacts.VerdictSkip
	default:
		return "quit"
	}
}

// PromptFPReason is shown only when verdict == VerdictFalsePositive.
// Returns one of artifacts.FP* constants. Free-form input is
// accepted and stored verbatim, so the taxonomy can grow without
// code changes.
func PromptFPReason(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprintln(w, "FP reason:")
	fmt.Fprintln(w, "  1. wrong_layer            (low-level missing → high-level claim)")
	fmt.Fprintln(w, "  2. insufficient_evidence  (absence-of-evidence reasoning)")
	fmt.Fprintln(w, "  3. architectural_remark   (observation, not bug)")
	fmt.Fprintln(w, "  4. upper_layer_invariant  (enforced elsewhere)")
	fmt.Fprintln(w, "  5. target_not_in_snippet  (claim from absent code)")
	fmt.Fprintln(w, "  6. already_dismissed      (arbiter said no_issue, leaked)")
	fmt.Fprintln(w, "  7. duplicate              (same root cause filed elsewhere)")
	fmt.Fprintln(w, "  8. out_of_scope           (true but outside focus)")
	fmt.Fprintln(w, "  9. other                  (Notes explains)")
	fmt.Fprint(w, "Choose [1-9 or full name]: ")
	if !r.Scan() {
		return ""
	}
	raw := strings.ToLower(strings.TrimSpace(r.Text()))
	switch raw {
	case "1":
		return artifacts.FPWrongLayer
	case "2":
		return artifacts.FPInsufficientEvidence
	case "3":
		return artifacts.FPArchitecturalRemark
	case "4":
		return artifacts.FPUpperLayerInvariant
	case "5":
		return artifacts.FPTargetNotInSnippet
	case "6":
		return artifacts.FPAlreadyDismissed
	case "7":
		return artifacts.FPDuplicate
	case "8":
		return artifacts.FPOutOfScope
	case "9", "other":
		return artifacts.FPOther
	}
	return raw // free-form / new vocabulary; stored verbatim
}

// PromptSeverityOverride asks for a severity correction. Returns
// "" when the reviewer keeps the arbiter's value (caller persists
// CorrectedSeverity only when non-empty).
func PromptSeverityOverride(r *bufio.Scanner, w io.Writer, current string) string {
	fmt.Fprintf(w, "Severity correction (high/medium/low) [enter=keep %s]: ", current)
	if !r.Scan() {
		return ""
	}
	text := strings.ToLower(strings.TrimSpace(r.Text()))
	switch text {
	case "high", "medium", "low":
		return text
	default:
		return ""
	}
}

// PromptConfidenceOverride asks for a confidence correction.
// Returns "" when the reviewer keeps the arbiter's value.
func PromptConfidenceOverride(r *bufio.Scanner, w io.Writer, current string) string {
	fmt.Fprintf(w, "Confidence correction (high/medium/low) [enter=keep %s]: ", current)
	if !r.Scan() {
		return ""
	}
	text := strings.ToLower(strings.TrimSpace(r.Text()))
	switch text {
	case "high", "medium", "low":
		return text
	default:
		return ""
	}
}

func PromptTags(r *bufio.Scanner, w io.Writer) []string {
	fmt.Fprint(w, "Tags (comma-separated): ")
	if !r.Scan() {
		return nil
	}
	raw := strings.TrimSpace(r.Text())
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var tags []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}

func PromptNotes(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Notes: ")
	if !r.Scan() {
		return ""
	}
	return strings.TrimSpace(r.Text())
}
