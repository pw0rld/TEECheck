package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
)

// observationCap is the planner's excerpt limit. It is an alias, not a
// number: the pages the browsing actions build are sized to
// observationlimits.MaxBytes, and a planner that cut at some other value
// would deliver a page sized for one limit under another, looking complete.
const observationCap = observationlimits.MaxBytes

// refHashLen is how much of the sha256 survives into the ref. Twelve hex
// characters is 48 bits over the observations of one run — a few hundred at
// most — and short enough that a ref can sit inside a prompt without costing
// a line of its own.
const refHashLen = 12

// MakeObservationRef names one observation for the life of a run.
//
// The identity is (sample, round, action index, output body). Two of those
// need explaining:
//
// The sample index is here because --samples N drives the planner N times,
// each starting from round 1, so (round, action index) repeats across
// samples. Without it a lead raised in sample 2 would cite sample 1's
// evidence — and the two samples explored different code on purpose.
//
// The output body is here so that repeating a call resolves to the same
// evidence while two different calls in one round stay distinct. It is
// passed as the blob reference rather than the body itself: the blob store
// is already content-addressed, so the ref inherits that addressing for
// free, and an observation with no blob (an empty output, or a run with no
// blob store) still gets a stable ref from the rest of the tuple.
//
// The phase — reconnaissance or investigation — is deliberately NOT part of
// it. It is narrative: the same sample passes through both.
func MakeObservationRef(runID string, sampleIndex, round, actionIndex int, outputBlob string) string {
	sum := sha256.Sum256([]byte(runID + "\x00" + outputBlob))
	return fmt.Sprintf("obs:%d:%d:%d:%s", sampleIndex, round, actionIndex,
		hex.EncodeToString(sum[:])[:refHashLen])
}

// ObservationSet is what a planner sample actually saw. It answers one
// question — was this ref produced by a successful action in this sample —
// and it is the only thing standing between a cited fact and an invented
// one.
//
// The zero value is usable and answers false to everything, which is the
// correct answer for a sample that has observed nothing yet.
type ObservationSet struct {
	ok map[string]bool
}

// Record files an observation under its ref. A failed action is recorded as
// failed rather than dropped: the difference between "never ran" and "ran
// and failed" is the difference between a gap and a negative result, and a
// caller that only ever saw the successes cannot tell them apart.
func (s *ObservationSet) Record(ref string, ok bool) {
	if ref == "" {
		return
	}
	if s.ok == nil {
		s.ok = map[string]bool{}
	}
	// A ref repeats only when the same call in the same round produced the
	// same body, so a later failure cannot contradict an earlier success.
	// Recording the successful one wins on the same principle.
	if ok || !s.ok[ref] {
		s.ok[ref] = ok
	}
}

// Observed reports whether this ref came from a successful action. A refused
// or errored action observed nothing, so it grounds nothing.
func (s ObservationSet) Observed(ref string) bool {
	return s.ok[ref]
}

// Len is the number of distinct refs recorded, successful or not.
func (s ObservationSet) Len() int { return len(s.ok) }

// excerpt bounds one observation and says so in the text the model reads.
//
// The failure it exists to stop is the silent cut: the planner used to
// truncate every observation to 4000 characters with no marker at all, so a
// 32 KB page of function cards reached the model as 4 KB that looked like
// the whole answer. A model cannot ask for the rest of something it does not
// know was cut.
//
// outputBlob is named in the marker so the full body is recoverable. When
// there is no blob store the marker says that instead of naming nothing.
func excerpt(s, outputBlob string) (string, bool) {
	if len(s) <= observationCap {
		return s, false
	}
	cut := s[:observationCap]
	// Back off to a rune boundary. A page cut mid-rune reaches the model as
	// a replacement character in the middle of an identifier, which reads as
	// data corruption rather than as a limit.
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	where := "the full body was not stored"
	if outputBlob != "" {
		where = "full body: " + outputBlob
	}
	return fmt.Sprintf("%s\n... (truncated at %d bytes of %d; %s)", cut, len(cut), len(s), where), true
}
