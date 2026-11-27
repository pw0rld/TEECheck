package planner

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
)

// A lead that cites "the producer does not write key.version" has to point
// at the observation that showed it. Without an id there is nothing to point
// at, and reason_fact_refs degrades to free text shaped like a citation —
// which is the same unevidenced anchor with extra steps.
func TestMakeObservationRef_IsStableAndDistinct(t *testing.T) {
	a := MakeObservationRef("run-1", 0, 3, 1, "sha256:aaa")
	again := MakeObservationRef("run-1", 0, 3, 1, "sha256:aaa")
	if a != again {
		t.Error("the same observation must produce the same ref")
	}
	for _, other := range []string{
		MakeObservationRef("run-1", 1, 3, 1, "sha256:aaa"), // different sample
		MakeObservationRef("run-1", 0, 4, 1, "sha256:aaa"), // different round
		MakeObservationRef("run-1", 0, 3, 2, "sha256:aaa"), // different action
		MakeObservationRef("run-1", 0, 3, 1, "sha256:bbb"), // different output
		MakeObservationRef("run-2", 0, 3, 1, "sha256:aaa"), // different run
	} {
		if a == other {
			t.Errorf("distinct observations collided on %s", a)
		}
	}
}

// --samples N drives this loop N times, each from round 1. A ref built
// without the sample index would let a lead raised in sample 2 cite sample
// 1's evidence — and the two samples are pointed at different code on
// purpose, so the citation would resolve to something the model never saw.
func TestMakeObservationRef_SamplesDoNotShareRefs(t *testing.T) {
	first := MakeObservationRef("run-1", 0, 3, 1, "")
	second := MakeObservationRef("run-1", 1, 3, 1, "")
	if first == second {
		t.Fatalf("two samples collided at round 3 action 1 on %s", first)
	}
}

// The page budget and the planner's excerpt must be the same number, or the
// page is sized for a limit that is not the one applied.
func TestObservationCap_HasExactlyOneDefinition(t *testing.T) {
	if observationCap != observationlimits.MaxBytes {
		t.Errorf("planner caps at %d, the shared limit is %d", observationCap, observationlimits.MaxBytes)
	}
}

// A silent cut is the failure mode: the model reads 4 KB of a 32 KB page and
// has no way to know the rest exists.
func TestExcerpt_MarksWhatItCut(t *testing.T) {
	long := strings.Repeat("x", observationlimits.MaxBytes*2)
	got, truncated := excerpt(long, "sha256:deadbeef")
	if !truncated {
		t.Fatal("an over-long output must report that it was cut")
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("the excerpt must say so in the text the model reads: %q", got[len(got)-120:])
	}
	// A marker that does not say where the rest went leaves the model with a
	// dead end instead of a pointer.
	if !strings.Contains(got, "sha256:deadbeef") {
		t.Errorf("the marker must name the blob holding the full body: %q", got[len(got)-120:])
	}
}

// A page built to the shared budget must arrive whole. This is the other
// half of the cap test: asserting only "not larger than the limit" catches a
// cap that is too generous and misses one that is too tight — and too tight
// is what actually happened, a 4000-character cut applied to 32 KB pages.
func TestExcerpt_APageBuiltToTheBudgetArrivesWhole(t *testing.T) {
	page := strings.Repeat("y", observationlimits.MaxBytes-len("THE_LAST_ONE")) + "THE_LAST_ONE"
	got, truncated := excerpt(page, "sha256:abc")
	if truncated {
		t.Fatalf("a %d-byte page was cut under a %d-byte budget", len(page), observationlimits.MaxBytes)
	}
	if !strings.HasSuffix(got, "THE_LAST_ONE") {
		t.Error("the end of a page that fits must survive the trip")
	}
}

// Cutting at a byte offset lands mid-rune on any non-ASCII body. A page that
// arrives with a replacement character inside an identifier reads as data
// corruption rather than as a limit.
func TestExcerpt_DoesNotCutARuneInHalf(t *testing.T) {
	// 3 bytes per rune, so byte offset MaxBytes falls inside a rune.
	body := strings.Repeat("三", observationlimits.MaxBytes)
	got, truncated := excerpt(body, "")
	if !truncated {
		t.Fatal("this body is over the cap")
	}
	if strings.ContainsRune(got, '�') {
		t.Error("the excerpt was cut mid-rune")
	}
}

// A ref that no successful action produced grounds nothing. The zero value
// answers false to everything, which is the right answer for a sample that
// has observed nothing yet.
func TestObservationSet_OnlySuccessfulActionsGround(t *testing.T) {
	var zero ObservationSet
	if zero.Observed("obs:0:1:0:abc") {
		t.Error("an empty set must not vouch for anything")
	}

	var s ObservationSet
	s.Record("obs:0:1:0:aaa", true)
	s.Record("obs:0:1:1:bbb", false)
	if !s.Observed("obs:0:1:0:aaa") {
		t.Error("a successful action's ref must ground a citation")
	}
	if s.Observed("obs:0:1:1:bbb") {
		t.Error("a failed action observed nothing and must ground nothing")
	}
	// Both are recorded: the difference between "never ran" and "ran and
	// failed" is the difference between a gap and a negative result.
	if s.Len() != 2 {
		t.Errorf("recorded %d refs, want both the success and the failure", s.Len())
	}
}

func TestObservationSetResolveRequiresUniqueSuccessfulCurrentSampleRef(t *testing.T) {
	var observed ObservationSet
	observed.Record("obs:2:3:0:aaa", true)
	observed.Record("obs:2:3:1:bbb", false)
	if full, ok := observed.Resolve("obs:2:3:0"); !ok || full != "obs:2:3:0:aaa" {
		t.Fatalf("unique shortened ref did not resolve: %q, %v", full, ok)
	}
	for _, ref := range []string{"obs:2:3:1", "obs:1:3:0", "obs:2:3", "obs:2:3:0:wrong"} {
		if full, ok := observed.Resolve(ref); ok {
			t.Fatalf("failed, other-sample or malformed ref resolved: %q -> %q", ref, full)
		}
	}
	observed.Record("obs:2:3:0:ccc", true)
	if full, ok := observed.Resolve("obs:2:3:0"); ok {
		t.Fatalf("ambiguous ref resolved: %q", full)
	}
	if full, ok := observed.Resolve("obs:2:3:0:aaa"); !ok || full != "obs:2:3:0:aaa" {
		t.Fatal("exact ref was rejected after an ambiguity in the shortened form")
	}
}
