package agentutil

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ExtractJSONObject(text string) (string, error) {
	start := strings.Index(text, "{")
	if start < 0 {
		return "", fmt.Errorf("no json object found")
	}
	depth := 0
	inString := false
	escaped := false
	for idx := start; idx < len(text); idx++ {
		ch := text[idx]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
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
				return text[start : idx+1], nil
			}
		}
	}
	return "", fmt.Errorf("unterminated json object")
}

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
