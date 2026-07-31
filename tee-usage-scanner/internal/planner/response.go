package planner

import (
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// LLMResponse is the structured response the planner expects from the
// LLM each round. The system prompt (BuildSystemPrompt) instructs the
// LLM to return exactly this shape.
type LLMResponse struct {
	Thought string               `json:"thought"`
	Actions []LLMRequestedAction `json:"actions"`
}

// LLMRequestedAction is one action the LLM wants to execute. Args is
// kept as a raw object so the planner can forward it to the handler
// without double-unmarshalling.
type LLMRequestedAction struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// ParseLLMResponse extracts a thought + actions object from an LLM
// text response. The LLM may return the JSON directly, wrap it in
// markdown code fences, or surround it with prose — llm.ExtractJSONObject
// handles all three.
func ParseLLMResponse(raw string) (LLMResponse, error) {
	var resp LLMResponse
	if err := llm.ExtractJSONObject(raw, &resp); err != nil {
		return LLMResponse{}, fmt.Errorf("parse llm response: %w", err)
	}
	if len(resp.Actions) == 0 {
		return LLMResponse{}, fmt.Errorf("llm response has no actions")
	}
	return resp, nil
}
