package sinks

import "strings"

// MatchSymbol reports whether `symbol` matches `glob`. The glob syntax
// is intentionally restricted in v1:
//
//   - A leading `*` matches any prefix (including empty).
//   - A trailing `*` matches any suffix (including empty).
//   - Both leading and trailing `*` may be present.
//   - Any other `*` (in the middle of the pattern) is treated as a
//     literal `*` character. This keeps the matcher predictable and
//     avoids the LLM accidentally writing globs that match too much.
//
// Exception: when a leading or trailing `*` is already present, any
// additional `*` within the pattern is also treated as a wildcard
// (sequential segment matching). This allows patterns like
// "attest::*::verify*" to match "attest::sgx::verify_quote".
// A pure middle-only `*` (e.g. "sgx_*_create") is still treated as a
// literal `*` character.
//
// Examples:
//
//	"sgx_create_report"   matches only "sgx_create_report"
//	"sgx_quote_*"         matches "sgx_quote_generate", "sgx_quote_"
//	"*::verify_quote"     matches "attest::verify_quote", "::verify_quote"
//	"*::verify_quote*"    matches "attest::verify_quote_extended"
//	"sgx_*_create"        matches NOTHING containing a `*` (literal)
//	"attest::*::verify*"  matches "attest::sgx::verify_quote"
//
// The matcher is case-sensitive — Rust symbols are case-sensitive and
// the catalog should preserve case.
func MatchSymbol(glob, symbol string) bool {
	leading := strings.HasPrefix(glob, "*")
	trailing := strings.HasSuffix(glob, "*")

	// If neither leading nor trailing wildcard, treat the glob as a
	// literal string (any internal * is a literal character).
	if !leading && !trailing {
		return symbol == glob
	}

	// Strip the leading and/or trailing *.
	core := glob
	if leading {
		core = core[1:]
	}
	if trailing && len(core) > 0 {
		core = core[:len(core)-1]
	}

	// Split core on any remaining * characters to get ordered segments.
	// This handles patterns like "attest::*::verify" (after trailing * stripped).
	segments := strings.Split(core, "*")

	switch {
	case leading && trailing:
		// Symbol must contain all segments in order.
		return matchSegmentsContains(symbol, segments)
	case leading:
		// Symbol must end with segments matched in order from the right.
		return matchSegmentsSuffix(symbol, segments)
	default: // trailing
		// Symbol must start with segments matched in order from the left.
		return matchSegmentsPrefix(symbol, segments)
	}
}

// matchSegmentsPrefix checks that symbol starts with segments[0], then
// contains segments[1], segments[2], … in order (each after the previous).
func matchSegmentsPrefix(symbol string, segments []string) bool {
	remaining := symbol
	for i, seg := range segments {
		if i == 0 {
			if !strings.HasPrefix(remaining, seg) {
				return false
			}
			remaining = remaining[len(seg):]
		} else {
			idx := strings.Index(remaining, seg)
			if idx < 0 {
				return false
			}
			remaining = remaining[idx+len(seg):]
		}
	}
	return true
}

// matchSegmentsSuffix checks that symbol ends with the last segment, and
// that all preceding segments appear in order before it.
func matchSegmentsSuffix(symbol string, segments []string) bool {
	if len(segments) == 0 {
		return true
	}
	last := segments[len(segments)-1]
	if !strings.HasSuffix(symbol, last) {
		return false
	}
	// Work on the prefix portion (everything before the suffix match).
	remaining := symbol[:len(symbol)-len(last)]
	for _, seg := range segments[:len(segments)-1] {
		idx := strings.Index(remaining, seg)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(seg):]
	}
	return true
}

// matchSegmentsContains checks that all segments appear in symbol in order.
func matchSegmentsContains(symbol string, segments []string) bool {
	remaining := symbol
	for _, seg := range segments {
		idx := strings.Index(remaining, seg)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(seg):]
	}
	return true
}

// MatchAny reports whether any glob in the slice matches the symbol.
func MatchAny(globs []string, symbol string) bool {
	for _, g := range globs {
		if MatchSymbol(g, symbol) {
			return true
		}
	}
	return false
}
