package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ExtractJSONObject(raw string, out any) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty llm response")
	}
	if err := json.Unmarshal([]byte(raw), out); err == nil {
		return nil
	}

	start := -1
	depth := 0
	for i, r := range raw {
		if r == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		}
		if r == '}' {
			depth--
			if depth == 0 && start >= 0 {
				candidate := raw[start : i+1]
				if err := json.Unmarshal([]byte(candidate), out); err == nil {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("could not extract json object from llm response")
}
