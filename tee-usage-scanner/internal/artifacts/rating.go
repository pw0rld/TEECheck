package artifacts

import "strings"

// RatingUnrated is the sentinel every Challenger rating field carries
// when the agent did not produce a value on the field's own scale.
//
// It is deliberately NOT a member of either rating vocabulary
// ("low"|"medium"|"high" for confidence, "proven"|"likely"|
// "theoretical"|"unlikely" for exploitability) and deliberately not the
// empty string: missing data must be distinguishable both from a real
// judgement and from a field nobody wrote. Until 2026-07-28 an
// unparseable Challenger rating silently became "theoretical", or worse
// was derived from the EXPERT's confidence — so the field whose whole
// purpose is independent judgement echoed the judgement it exists to
// challenge, and every downstream reader took the echo for a second
// opinion.
const RatingUnrated = "unrated"

// FormatRating renders a Challenger rating for a reader — human or
// model. A legal value passes through untouched, so nothing about a
// normal run changes. Missing data is spelled out instead of being
// printed as a bare token that scans like a verdict or as a blank that
// scans like an omission.
//
// Every place a Challenger rating reaches a prompt or a review packet
// goes through here: the phase-2 prompt (internal/challenger),
// the verifier prompt, the arbiter prompt, and the human review packet.
func FormatRating(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", RatingUnrated:
		return RatingUnrated + " (the Challenger returned no value on this field's scale; this is missing data, not a low rating)"
	default:
		return value
	}
}

// SchemaVersionChallengerNormalizationsV1 versions the record below.
const SchemaVersionChallengerNormalizationsV1 = "teecheck.challenger_normalizations.v1"

// NormalizationAdjustment records one place the Challenger stage
// replaced what the model actually said with something else. It mirrors
// investigations.Adjustment / invariants.Adjustment /
// architecture.StateAdjustment ("recorded, not just applied"), with the
// addition of From/To: for a rating field the *previous value* is the
// whole point of the record, and a Reason string alone cannot be
// mechanically compared against what the artifact ended up saying.
type NormalizationAdjustment struct {
	CaseID string `json:"case_id"`
	// Field is the artifact field that was replaced:
	// "confidence" (ChallengerIndependentView) | "exploitability" (Challenge).
	Field string `json:"field"`
	// Kind is "reask_recovered" (the first reply was off-vocabulary and
	// one corrective re-ask produced a legal value) or "unrated_fallback"
	// (neither reply was legal, so the field is missing data).
	Kind string `json:"kind"`
	// From is the model's original, verbatim (trimmed) value.
	From string `json:"from"`
	// To is what the artifact ended up carrying.
	To string `json:"to"`
	// Reason names every rejected value and the vocabulary they failed.
	Reason string `json:"reason"`
}

// ChallengerNormalizations is the per-run record persisted next to the
// Challenger's artifacts. It is written on EVERY run, including runs
// with no adjustments at all, so an empty Adjustments list is positive
// evidence that nothing was rewritten rather than an absent file that
// could equally mean "this run predates the record".
type ChallengerNormalizations struct {
	SchemaVersion string                    `json:"schema_version"`
	RunID         string                    `json:"run_id,omitempty"`
	AgentID       string                    `json:"agent_id,omitempty"`
	Adjustments   []NormalizationAdjustment `json:"adjustments"`
}
