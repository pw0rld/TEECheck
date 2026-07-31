package artifacts

// Verdict values written by `teecheck review`. Phase 1.5 expanded the
// vocabulary so reviewers can distinguish "scanner was wrong" from
// "scanner was right but at a non-vulnerability layer" from "I cannot
// tell from the snippet alone". The earlier 4-verdict design conflated
// design risk with FP, which would have biased downstream metrics.
//
// Backward compatibility:
//   - legacy strings ("confirmed", "dismissed", "inconclusive",
//     "needs_more_context") are accepted on read and mapped by
//     NormalizeVerdict
//   - new writes use the long names below
const (
	VerdictTruePositive    = "true_positive"
	VerdictFalsePositive   = "false_positive"
	VerdictNeedsContext    = "needs_context"
	VerdictDesignRisk      = "design_risk"
	VerdictNoIssueObserved = "no_issue_observed"
	VerdictSkip            = "skip"
)

// ReasonCode is a closed taxonomy explaining *why* a finding got the
// non-TP verdict it did. The codes describe failure modes of the
// scanner, not categories of bug — they're the levers downstream
// improvements (planner / expert / verifier prompts) hook onto.
//
// Phase 1.5 replaced the earlier FP-only taxonomy. ReasonCode applies
// to any non-TP verdict (false_positive, needs_context, design_risk,
// no_issue_observed). Unknown values are stored verbatim so reviewers
// can extend without code changes; recurring new codes should be
// promoted to named constants here.
const (
	// ReasonOuterValidationMissed: scanner flagged a missing check
	// at one layer, but the check is enforced by an outer validator
	// (signature, timestamp, quote status, debug, TCB, identity).
	ReasonOuterValidationMissed = "outer_validation_missed"

	// ReasonWrapperPolicySplit: the policy is enforced jointly by a
	// wrapper and an inner function; scanner saw only one half.
	ReasonWrapperPolicySplit = "wrapper_policy_split"

	// ReasonSnippetTruncation: the cited snippet was truncated such
	// that the relevant code path is not visible — scanner reasoned
	// from absence-of-code rather than evidence-of-absence.
	ReasonSnippetTruncation = "snippet_truncation"

	// ReasonProtocolSemanticsMissed: scanner missed an invariant
	// established by the protocol (handshake order, message kind,
	// TLS state) rather than by code in the snippet.
	ReasonProtocolSemanticsMissed = "protocol_semantics_missed"

	// ReasonCfgContextMissed: scanner ignored a `cfg(...)` gate that
	// excludes the flagged path from the build under audit.
	ReasonCfgContextMissed = "cfg_context_missed"

	// ReasonFeatureFlagContextMissed: scanner ignored a runtime
	// feature flag that disables the flagged path in the deployed
	// configuration.
	ReasonFeatureFlagContextMissed = "feature_flag_context_missed"

	// ReasonOther: catchall — ReviewRecord.Notes should explain.
	ReasonOther = "other"
)

// NormalizeVerdict maps legacy verdict strings to the Phase 1.5
// vocabulary so old review_records.jsonl files keep round-tripping.
// Unknown values pass through unchanged.
func NormalizeVerdict(v string) string {
	switch v {
	case "confirmed":
		return VerdictTruePositive
	case "dismissed":
		return VerdictFalsePositive
	case "inconclusive", "needs_more_context":
		return VerdictNeedsContext
	}
	return v
}

// IsDefinitiveVerdict reports whether v means the reviewer made a
// terminal call about scanner correctness (TP or FP). Used as the
// denominator for fp_rate_definitive.
func IsDefinitiveVerdict(v string) bool {
	switch NormalizeVerdict(v) {
	case VerdictTruePositive, VerdictFalsePositive:
		return true
	}
	return false
}

// IsCandidateVerdict reports whether the finding was treated as a
// real candidate vulnerability by the reviewer (TP, FP, NC, DR).
// VerdictNoIssueObserved is excluded because it represents scanner
// self-rejection rather than a candidate the reviewer evaluated.
// Used as the denominator for fp_rate_reviewed and non_tp_rate_reviewed.
func IsCandidateVerdict(v string) bool {
	switch NormalizeVerdict(v) {
	case VerdictTruePositive, VerdictFalsePositive,
		VerdictNeedsContext, VerdictDesignRisk:
		return true
	}
	return false
}

// EffectiveReasonCode returns the reviewer's reason code, falling
// back to the legacy Phase 1 FPReason field when ReasonCode is unset.
// Consumers should always call this rather than reading ReasonCode
// directly so older review_records.jsonl files keep producing useful
// reason-distribution stats.
func (r ReviewRecord) EffectiveReasonCode() string {
	if r.ReasonCode != "" {
		return r.ReasonCode
	}
	return r.FPReason
}

// EffectiveSeverity returns the reviewer's corrected severity,
// falling back to the legacy Severity field when CorrectedSeverity is
// unset. `teecheck review` only ever writes CorrectedSeverity, so a
// consumer that reads the raw Severity field silently gets "" for
// every record written since the Phase 1.5 schema bump. Read this
// instead — it is the one place the preference documented on
// ReviewRecord.Severity is implemented.
func (r ReviewRecord) EffectiveSeverity() string {
	if r.CorrectedSeverity != "" {
		return r.CorrectedSeverity
	}
	return r.Severity
}
