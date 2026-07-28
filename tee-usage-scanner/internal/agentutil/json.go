package agentutil

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractJSONObject returns the span of text that is the JSON object an LLM
// meant to send, from a reply that may also contain prose, markdown fences,
// or source code.
//
// It tries, in order:
//
//  1. The whole (trimmed) text, if it is already a JSON object. This is the
//     common case when the model complied with the prompt, and it costs one
//     json.Valid call.
//  2. The text with markdown code fences (```json ... ``` or ``` ... ```)
//     stripped. A fenced-but-otherwise-perfect object never reaches the scan.
//  3. A scan over every "{" offset in turn. Each offset is taken as a
//     candidate start, extended to its matching "}" by depth counting that
//     ignores braces inside JSON strings, and the resulting span is then
//     *verified to parse as JSON*. Candidates that balance but do not parse
//     are skipped and the scan continues.
//
// Step 3's verification is the point. Committing to the first "{" byte, as
// this function used to, means a brace inside prose or inside quoted C source
// hijacks the extraction: "if (x) { ok(); }" balances perfectly and was
// returned as "the model's answer", and an unbalanced "foo() {" earlier in
// the reply consumed the rest of the text and hid a perfectly good object
// further down.
//
// A reply whose top-level value is a JSON array is reported as such rather
// than mined for the first object inside it, because every caller wants a
// single object and silently unwrapping an array is a guess.
//
// The returned span is verbatim: no repair is applied, so UnmarshalJSONObject
// remains the only place that rewrites the model's bytes.
func ExtractJSONObject(text string) (string, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", fmt.Errorf("no json object found: input is empty")
	}

	// Steps 1 and 2.
	body := stripCodeFences(trimmed)
	if isJSONObject(trimmed) {
		return trimmed, nil
	}
	if body != trimmed && isJSONObject(body) {
		return body, nil
	}

	// A top-level array is a distinct failure from "found nothing usable".
	if strings.HasPrefix(body, "[") && json.Valid([]byte(body)) {
		return "", fmt.Errorf("expected a json object, got a json array")
	}

	// Step 3.
	candidates := 0
	for i := 0; i < len(body); i++ {
		if body[i] != '{' {
			continue
		}
		candidates++
		end, ok := findMatchingBrace(body, i)
		if !ok {
			continue
		}
		if span := body[i : end+1]; isJSONObject(span) {
			return span, nil
		}
	}

	if candidates == 0 {
		return "", fmt.Errorf("no json object found: no '{' in %d bytes of text", len(body))
	}
	return "", fmt.Errorf(
		"no json object found: examined %d '{' candidate(s) in %d bytes, none parsed as json",
		candidates, len(body))
}

// isJSONObject reports whether s is a JSON object.
//
// The fixRawNewlinesInJSON fallback is deliberate. Models routinely emit
// literal newlines inside string values, and UnmarshalJSONObject has always
// repaired those on retry. If candidate verification used bare json.Valid,
// a reply that today parses fine would suddenly be rejected as "not a
// candidate" — a regression introduced by the very check meant to make
// extraction safer. A candidate that parses only after newline repair is
// still unambiguously the right candidate: the repair rewrites only control
// characters that are already inside a quoted string, so it cannot turn a
// code fragment such as "{ ok(); }" into valid JSON.
func isJSONObject(s string) bool {
	if !strings.HasPrefix(s, "{") {
		return false
	}
	if json.Valid([]byte(s)) {
		return true
	}
	return json.Valid([]byte(fixRawNewlinesInJSON(s)))
}

// stripCodeFences removes the markdown code fence wrapping that LLMs produce
// around JSON. It is conservative: only a fence that opens the whole text is
// stripped. Prose-wrapped fences are left to the candidate scan, which finds
// the object inside them anyway.
func stripCodeFences(trimmed string) string {
	var inner string
	switch {
	case strings.HasPrefix(trimmed, "```json"):
		inner = strings.TrimPrefix(trimmed, "```json")
	case strings.HasPrefix(trimmed, "```"):
		inner = strings.TrimPrefix(trimmed, "```")
	default:
		return trimmed
	}
	inner = strings.TrimSpace(inner)
	inner = strings.TrimSuffix(inner, "```")
	if inner = strings.TrimSpace(inner); inner == "" {
		return trimmed
	}
	return inner
}

// findMatchingBrace returns the index of the "}" closing the "{" at openPos,
// or ok=false if the text runs out first. Braces and quotes inside JSON string
// values are ignored, so a literal "{" in a string value cannot unbalance the
// count.
func findMatchingBrace(s string, openPos int) (int, bool) {
	if openPos >= len(s) || s[openPos] != '{' {
		return 0, false
	}
	depth := 0
	inString := false
	escaped := false
	for i := openPos; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// UnmarshalJSONObject extracts the JSON object from an LLM reply and
// unmarshals it into out.
func UnmarshalJSONObject[T any](text string, out *T) error {
	obj, err := ExtractJSONObject(text)
	if err != nil {
		return err
	}
	// Try direct parse first
	if err := json.Unmarshal([]byte(obj), out); err == nil {
		return nil
	}
	// Fix raw newlines inside JSON string values and retry
	fixed := fixRawNewlinesInJSON(obj)
	if err := json.Unmarshal([]byte(fixed), out); err != nil {
		return fmt.Errorf("parse json object: %w", err)
	}
	return nil
}

// fixRawNewlinesInJSON replaces unescaped newlines inside JSON string values
// with \\n so json.Unmarshal can parse them.
func fixRawNewlinesInJSON(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	inString := false
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inString {
			if escaped {
				escaped = false
				out.WriteByte(ch)
				continue
			}
			if ch == '\\' {
				escaped = true
				out.WriteByte(ch)
				continue
			}
			if ch == '"' {
				inString = false
				out.WriteByte(ch)
				continue
			}
			if ch == '\n' {
				out.WriteString("\\n")
				continue
			}
			if ch == '\r' {
				out.WriteString("\\r")
				continue
			}
			if ch == '\t' {
				out.WriteString("\\t")
				continue
			}
			out.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inString = true
		}
		out.WriteByte(ch)
	}
	return out.String()
}
