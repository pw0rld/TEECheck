package review

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// PromptVerdict prompts for the Phase 1.5 5-verdict vocabulary plus
// skip/quit. The five non-skip verdicts encode meaningfully different
// reviewer judgments and downstream metric denominators differ
// accordingly — see IsDefinitiveVerdict / IsCandidateVerdict.
//
// Returns one of artifacts.Verdict* constants, or the special
// sentinel "quit" to stop the review session entirely.
func PromptVerdict(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprintln(w, "Verdict?")
	fmt.Fprintln(w, "  [t] true_positive       — scanner was right, real bug")
	fmt.Fprintln(w, "  [f] false_positive      — scanner was wrong, no bug here")
	fmt.Fprintln(w, "  [n] needs_context       — cannot tell from snippet alone")
	fmt.Fprintln(w, "  [d] design_risk         — architectural concern, not a bug")
	fmt.Fprintln(w, "  [o] no_issue_observed   — scanner self-rejected this finding")
	fmt.Fprintln(w, "  [s] skip                — defer this finding")
	fmt.Fprintln(w, "  [q] quit                — end review session")
	fmt.Fprint(w, "> ")
	if !r.Scan() {
		return "quit"
	}
	switch strings.ToLower(strings.TrimSpace(r.Text())) {
	case "t", "tp", "true_positive", "true positive":
		return artifacts.VerdictTruePositive
	case "f", "fp", "false_positive", "false positive":
		return artifacts.VerdictFalsePositive
	case "n", "nc", "nmc", "needs_context", "needs context",
		"needs_more_context", "needs more context":
		return artifacts.VerdictNeedsContext
	case "d", "dr", "design_risk", "design risk":
		return artifacts.VerdictDesignRisk
	case "o", "nio", "no_issue", "no_issue_observed", "no issue observed":
		return artifacts.VerdictNoIssueObserved
	case "s", "skip":
		return artifacts.VerdictSkip
	default:
		return "quit"
	}
}

// PromptReasonCode is shown for every non-TP verdict (FP, needs_context,
// design_risk, no_issue_observed). The taxonomy describes scanner
// failure modes — the levers downstream prompt / planner / verifier
// improvements hook onto.
//
// Returns one of artifacts.Reason* constants. Free-form input is
// accepted and stored verbatim, so the taxonomy can grow without
// code changes.
func PromptReasonCode(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprintln(w, "Reason code:")
	fmt.Fprintln(w, "  1. outer_validation_missed       (signature/timestamp/quote/TCB enforced upstream)")
	fmt.Fprintln(w, "  2. wrapper_policy_split          (policy enforced jointly by wrapper + inner)")
	fmt.Fprintln(w, "  3. snippet_truncation            (relevant code path not in cited snippet)")
	fmt.Fprintln(w, "  4. protocol_semantics_missed     (handshake / message-kind / TLS state)")
	fmt.Fprintln(w, "  5. cfg_context_missed            (cfg(...) gate excludes flagged path)")
	fmt.Fprintln(w, "  6. feature_flag_context_missed   (runtime flag disables flagged path)")
	fmt.Fprintln(w, "  7. other                         (Notes explains)")
	fmt.Fprint(w, "Choose [1-7 or full name, enter to skip]: ")
	if !r.Scan() {
		return ""
	}
	raw := strings.ToLower(strings.TrimSpace(r.Text()))
	switch raw {
	case "":
		return ""
	case "1":
		return artifacts.ReasonOuterValidationMissed
	case "2":
		return artifacts.ReasonWrapperPolicySplit
	case "3":
		return artifacts.ReasonSnippetTruncation
	case "4":
		return artifacts.ReasonProtocolSemanticsMissed
	case "5":
		return artifacts.ReasonCfgContextMissed
	case "6":
		return artifacts.ReasonFeatureFlagContextMissed
	case "7", "other":
		return artifacts.ReasonOther
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
