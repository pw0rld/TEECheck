package citations

import (
	"errors"
	"os"
	"strings"
)

// Validation statuses surfaced to verifier prompts so the LLM can
// distinguish facts whose citations still hold from facts whose
// citations drifted, never had bytes attached, or could not be
// checked because the repo wasn't available.
//
// Why four states instead of three:
//   - valid       :  every citation on the fact still resolves and
//                    its sha256 matches the live bytes
//   - stale       :  at least one citation drifted (sha256 mismatch,
//                    file missing, line range invalid). The fact's
//                    text may still be true in spirit, but the
//                    specific evidence the agent attached has moved
//                    or disappeared. Reason names the first failure.
//   - unanchored  :  the fact has no citations attached (the agent
//                    asserted without producing evidence). Distinct
//                    from stale because the agent never claimed to
//                    have anchored bytes.
//   - unresolved  :  validation could not run because repoRoot is
//                    empty or does not exist on disk. This shows up
//                    when stats / verifier replays an artifact-only
//                    run without a live checkout. Lumped into stale,
//                    a missing checkout would silently flag every
//                    fact as drifted; explicit "unresolved" tells
//                    consumers "we don't know" rather than "we know
//                    it broke".
const (
	StatusValid      = "valid"
	StatusStale      = "stale"
	StatusUnanchored = "unanchored"
	StatusUnresolved = "unresolved"
)

// CitationValidation is the per-fact result of ValidateFacts. It is
// the structured form the verifier persists in
// VerificationMemo.ExpertCitationValidation, alongside any free-form
// notes a human reviewer might leave.
type CitationValidation struct {
	FactText string       `json:"fact_text"`
	Status   string       `json:"status"`
	Reason   string       `json:"reason,omitempty"`
	Cited    []CitedBytes `json:"cited,omitempty"`
}

// ValidateFacts walks the supplied cited-fact list and returns one
// CitationValidation per fact. The semantics:
//
//   - len(fact.Cited) == 0       → StatusUnanchored
//   - repoRoot empty or missing   → StatusUnresolved (Reason explains)
//   - every citation validates    → StatusValid
//   - any citation fails          → StatusStale (Reason names the
//                                    first failing citation's error)
//
// Strict semantics for stale: a fact backed by 5 citations where 1
// drifted is reported as stale. Verifier prompts can choose how to
// surface that to the model — a partial-stale fact is not the same
// trust-level as a fully-fresh one.
func ValidateFacts(facts []CitedFact, repoRoot string) []CitationValidation {
	canValidate := repoRoot != ""
	if canValidate {
		if _, err := os.Stat(repoRoot); err != nil {
			canValidate = false
		}
	}

	out := make([]CitationValidation, 0, len(facts))
	for _, f := range facts {
		v := CitationValidation{
			FactText: f.Text,
			Cited:    f.Cited,
		}
		switch {
		case len(f.Cited) == 0:
			v.Status = StatusUnanchored
		case !canValidate:
			v.Status = StatusUnresolved
			v.Reason = "repo not available for validation"
		default:
			v.Status = StatusValid
			for _, c := range f.Cited {
				if err := Validate(c, repoRoot); err != nil {
					v.Status = StatusStale
					v.Reason = trimError(err)
					break
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// trimError flattens errors.Is-wrapped citation errors to a single
// short line suitable for embedding in prompts and JSON. The full
// chain is preserved by callers via errors.Is on the original.
func trimError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case errors.Is(err, ErrSHA256Mismatch):
		// "citation: sha256 drifted: file=... lines=..." → keep
	case errors.Is(err, ErrFileMissing):
	case errors.Is(err, ErrLineOutOfRange):
	case errors.Is(err, ErrInvalidLineRange):
	case errors.Is(err, ErrNotResolvable):
	}
	if i := strings.Index(msg, "\n"); i > 0 {
		msg = msg[:i]
	}
	return msg
}
