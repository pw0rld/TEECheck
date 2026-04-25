package artifacts

// Verdict values written by `teecheck review`. The Phase 1 verdict
// vocabulary is explicit about ground-truth semantics rather than
// the older "confirmed/dismissed/inconclusive" trio, which conflated
// arbiter language with reviewer judgment.
//
// Backward compatibility:
//   - legacy strings ("confirmed", "dismissed", "inconclusive")
//     persisted in old review_records.jsonl files are accepted on
//     read and mapped to the new vocabulary by NormalizeVerdict
//   - new writes use the long names below
const (
	VerdictTruePositive     = "true_positive"
	VerdictFalsePositive    = "false_positive"
	VerdictNeedsMoreContext = "needs_more_context"
	VerdictSkip             = "skip"
)

// FPReason is a closed taxonomy for *why* a finding was marked
// false_positive. Stored on ReviewRecord.FPReason. The enum was
// derived from the user's hand-review of the oasis-core 6/6 FP run
// — the categories below cover every concrete reason that came up.
//
// Unknown values are stored verbatim (not validated) so reviewers
// can extend the vocabulary without code changes; new common cases
// should eventually be promoted into named constants here.
const (
	// FPWrongLayer: the finding is at the wrong abstraction level —
	// e.g. low-level "no policy check" upgraded to high-level
	// "accepts unauthorized enclaves" when policy is enforced
	// elsewhere.
	FPWrongLayer = "wrong_layer"

	// FPInsufficientEvidence: claim rests on absence-of-evidence
	// (target not in snippet, function body unseen) rather than
	// evidence-of-absence.
	FPInsufficientEvidence = "insufficient_evidence"

	// FPArchitecturalRemark: observation about architecture or
	// code style, not a security bug.
	FPArchitecturalRemark = "architectural_remark"

	// FPUpperLayerInvariant: an upper layer enforces the property
	// the finding claims is missing in this layer.
	FPUpperLayerInvariant = "upper_layer_invariant"

	// FPTargetNotInSnippet: the target symbol the finding is about
	// is not visible in the case pack snippets — claim was made
	// from absence-of-code rather than code analysis.
	FPTargetNotInSnippet = "target_not_in_snippet"

	// FPAlreadyDismissed: the arbiter itself emitted
	// no_issue_observed for this finding; it should have been
	// filtered before reaching the report.
	FPAlreadyDismissed = "already_dismissed"

	// FPDuplicate: same root cause already filed under another
	// finding.
	FPDuplicate = "duplicate"

	// FPOutOfScope: the claim is true but outside the audit's
	// stated scope (focus area).
	FPOutOfScope = "out_of_scope"

	// FPOther: catchall; ReviewRecord.Notes should explain.
	FPOther = "other"
)

// NormalizeVerdict maps legacy verdict strings to the Phase 1
// vocabulary so old review_records.jsonl files keep round-tripping.
// Unknown values pass through unchanged.
func NormalizeVerdict(v string) string {
	switch v {
	case "confirmed":
		return VerdictTruePositive
	case "dismissed":
		return VerdictFalsePositive
	case "inconclusive":
		return VerdictNeedsMoreContext
	}
	return v
}
