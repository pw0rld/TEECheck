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
	if err := json.Unmarshal([]byte(obj), out); err != nil {
		return fmt.Errorf("parse json object: %w", err)
	}
	return nil
}
