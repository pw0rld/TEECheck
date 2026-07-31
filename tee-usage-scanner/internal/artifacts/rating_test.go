package artifacts

import (
	"strings"
	"testing"
)

// A legal rating must reach the reader byte-for-byte: FormatRating is a
// legibility shim for missing data, not a rewriter.
func TestFormatRating_PassesLegalValuesThrough(t *testing.T) {
	for _, value := range []string{
		"low", "medium", "high",
		"proven", "likely", "theoretical", "unlikely",
	} {
		if got := FormatRating(value); got != value {
			t.Errorf("FormatRating(%q) = %q; legal ratings must pass through unchanged", value, got)
		}
	}
}

// The whole point of RatingUnrated is that a reader — model or human —
// cannot mistake it for a verdict or overlook it as a blank.
func TestFormatRating_SpellsOutMissingData(t *testing.T) {
	for _, value := range []string{"", RatingUnrated, "  UNRATED "} {
		got := FormatRating(value)
		if !strings.Contains(got, RatingUnrated) {
			t.Errorf("FormatRating(%q) = %q; must name the unrated state", value, got)
		}
		if !strings.Contains(got, "missing data") {
			t.Errorf("FormatRating(%q) = %q; must say this is missing data, not a low rating", value, got)
		}
		if strings.TrimSpace(got) == "" {
			t.Errorf("FormatRating(%q) rendered blank", value)
		}
	}
}

// RatingUnrated must not collide with either vocabulary, or a
// downstream reader filtering on legal values would silently accept it
// as a judgement.
func TestRatingUnrated_IsNotAVocabularyMember(t *testing.T) {
	for _, value := range []string{
		"low", "medium", "high",
		"proven", "likely", "theoretical", "unlikely",
	} {
		if RatingUnrated == value {
			t.Fatalf("RatingUnrated collides with the legal rating %q", value)
		}
	}
}
