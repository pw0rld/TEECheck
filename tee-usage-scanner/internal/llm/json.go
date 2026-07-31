package llm

import (
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
)

// ExtractJSONObject finds a JSON object embedded in an arbitrary LLM text
// response and unmarshals it into out. It handles a response that is already
// valid JSON, one wrapped in markdown code fences, and one surrounded by
// prose or source code.
//
// The extraction itself lives in agentutil.UnmarshalJSONObject. This package
// used to carry a second, independently maintained copy of the same
// brace-scanning and fence-stripping logic; the two drifted (only one of them
// verified that a balanced brace span actually parses, and only the other
// repaired raw newlines inside string values), so callers got different
// answers for the same model reply depending on which one they happened to
// call. There is now one implementation and this is a thin adapter to it.
//
// Passing &out — a *any holding a non-nil pointer — is what encoding/json's
// indirect() is built for: it unwraps the interface and decodes into the
// caller's concrete value.
func ExtractJSONObject(raw string, out any) error {
	if err := agentutil.UnmarshalJSONObject(raw, &out); err != nil {
		return fmt.Errorf("llm response: %w", err)
	}
	return nil
}
