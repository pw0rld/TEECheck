package sinks_test

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

func TestMatchSymbol_ExactMatch(t *testing.T) {
	if !sinks.MatchSymbol("sgx_create_report", "sgx_create_report") {
		t.Fatal("exact match should succeed")
	}
	if sinks.MatchSymbol("sgx_create_report", "sgx_create_report_v2") {
		t.Fatal("exact match should not match suffix")
	}
}

func TestMatchSymbol_TrailingWildcard(t *testing.T) {
	if !sinks.MatchSymbol("sgx_quote_*", "sgx_quote_generate") {
		t.Fatal("trailing * should match suffix")
	}
	if !sinks.MatchSymbol("sgx_quote_*", "sgx_quote_") {
		t.Fatal("trailing * should match empty suffix")
	}
	if sinks.MatchSymbol("sgx_quote_*", "sgx_qu") {
		t.Fatal("trailing * should not match shorter prefix")
	}
}

func TestMatchSymbol_LeadingWildcard(t *testing.T) {
	if !sinks.MatchSymbol("*::verify_quote", "attest::verify_quote") {
		t.Fatal("leading * should match prefix")
	}
	if !sinks.MatchSymbol("*::verify_quote", "::verify_quote") {
		t.Fatal("leading * should match empty prefix")
	}
}

func TestMatchSymbol_DoubleWildcard(t *testing.T) {
	if !sinks.MatchSymbol("*::verify_quote*", "attest::verify_quote_extended") {
		t.Fatal("double * should match prefix and suffix")
	}
	if !sinks.MatchSymbol("*::verify_quote*", "::verify_quote") {
		t.Fatal("double * should match minimal form")
	}
}

func TestMatchSymbol_MidWildcardNotSupported(t *testing.T) {
	// We only support leading and trailing *. A pattern like
	// "sgx_*_create" with a middle * is not handled — document
	// the limitation explicitly via a test.
	// The matcher should treat the middle * as a literal character,
	// so this should NOT match "sgx_quote_create".
	if sinks.MatchSymbol("sgx_*_create", "sgx_quote_create") {
		t.Fatal("middle * should not be treated as wildcard (v1 limitation)")
	}
}

func TestMatchSymbol_PathSeparators(t *testing.T) {
	// "::" is not special — it's just literal characters in a glob.
	if !sinks.MatchSymbol("attest::*::verify*", "attest::sgx::verify_quote") {
		t.Fatal("multi-segment glob should work")
	}
}

func TestMatchAny_FirstHit(t *testing.T) {
	globs := []string{"foo_*", "bar_*", "baz_*"}
	if !sinks.MatchAny(globs, "bar_thing") {
		t.Fatal("MatchAny should hit middle glob")
	}
	if sinks.MatchAny(globs, "qux_thing") {
		t.Fatal("MatchAny should miss when no glob matches")
	}
	if sinks.MatchAny(nil, "anything") {
		t.Fatal("MatchAny on nil should return false")
	}
}

func TestMatchSymbol_EmptyGlob(t *testing.T) {
	if !sinks.MatchSymbol("", "") {
		t.Fatal("empty matches empty")
	}
	if sinks.MatchSymbol("", "anything") {
		t.Fatal("empty should not match non-empty")
	}
}
