package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractJSONObject finds and unmarshals a JSON object embedded in an
// arbitrary LLM text response. It handles three common cases:
//
//  1. The response is already valid JSON.
//  2. The response is wrapped in markdown code fences (```json ... ```).
//  3. The response has extra prose before or after the JSON, or has
//     malformed wrapping (e.g. a stray leading "{" that unbalances the
//     brace depth).
//
// The extractor iterates every "{" in the text, treats each as a
// candidate start position, walks forward with depth tracking, and
// tries to unmarshal any balanced substring it finds. The first
// substring that parses successfully wins.
//
// This greedy approach tolerates malformed wrappers that upstream
// JSON extractors reject.
func ExtractJSONObject(raw string, out any) error {
	raw = strings.TrimSpace(stripCodeFences(raw))
	if raw == "" {
		return fmt.Errorf("empty llm response")
	}
	// Fast path: whole response is already JSON.
	if err := json.Unmarshal([]byte(raw), out); err == nil {
		return nil
	}
	// Slow path: try each `{` position as a candidate start.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '{' {
			continue
		}
		end, ok := findMatchingBrace(raw, i)
		if !ok {
			continue
		}
		candidate := raw[i : end+1]
		if err := json.Unmarshal([]byte(candidate), out); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not extract json object from llm response")
}

// stripCodeFences removes the most common markdown code fence
// wrapping patterns that LLMs produce. Conservative — only strips
// well-formed fences; leaves malformed wrapping to the extractor's
// greedy scan.
func stripCodeFences(raw string) string {
	trimmed := strings.TrimSpace(raw)
	// ```json\n...\n```
	if strings.HasPrefix(trimmed, "```json") {
		trimmed = strings.TrimPrefix(trimmed, "```json")
		trimmed = strings.TrimSpace(trimmed)
		trimmed = strings.TrimSuffix(trimmed, "```")
		return strings.TrimSpace(trimmed)
	}
	// ```\n...\n```
	if strings.HasPrefix(trimmed, "```") {
		trimmed = strings.TrimPrefix(trimmed, "```")
		trimmed = strings.TrimSpace(trimmed)
		trimmed = strings.TrimSuffix(trimmed, "```")
		return strings.TrimSpace(trimmed)
	}
	return raw
}

// findMatchingBrace returns the index of the `}` that closes the `{`
// at position openPos, or ok=false if unbalanced. Ignores braces that
// appear inside double-quoted strings (to avoid matching literal { in
// JSON string values).
func findMatchingBrace(s string, openPos int) (int, bool) {
	if openPos >= len(s) || s[openPos] != '{' {
		return 0, false
	}
	depth := 0
	inString := false
	escape := false
	for i := openPos; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}
