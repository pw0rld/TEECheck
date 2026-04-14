package planner_test

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestParseLLMResponse_DirectJSON(t *testing.T) {
	raw := `{"thought":"look around","actions":[{"name":"list_dir","args":{"path":"."}}]}`
	resp, err := planner.ParseLLMResponse(raw)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if resp.Thought != "look around" {
		t.Errorf("Thought = %q", resp.Thought)
	}
	if len(resp.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(resp.Actions))
	}
	if resp.Actions[0].Name != "list_dir" {
		t.Errorf("Name = %q", resp.Actions[0].Name)
	}
}

func TestParseLLMResponse_WrappedInMarkdown(t *testing.T) {
	raw := "Here is my plan:\n```json\n{\"thought\":\"t\",\"actions\":[{\"name\":\"done\",\"args\":{\"summary\":\"x\",\"candidates\":[]}}]}\n```\n"
	resp, err := planner.ParseLLMResponse(raw)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if resp.Actions[0].Name != "done" {
		t.Errorf("Name = %q", resp.Actions[0].Name)
	}
}

func TestParseLLMResponse_NoActionsRejected(t *testing.T) {
	raw := `{"thought":"thinking...","actions":[]}`
	_, err := planner.ParseLLMResponse(raw)
	if err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestParseLLMResponse_Garbage(t *testing.T) {
	_, err := planner.ParseLLMResponse("this is not json at all")
	if err == nil {
		t.Fatal("expected error for garbage")
	}
}

// Regression: GLM occasionally returns a malformed markdown code
// fence where the opening backticks are corrupted into a bare "{"
// followed by "json" on its own line, leaving an unbalanced outer
// brace. The extractor must still find the inner valid JSON object.
func TestParseLLMResponse_MalformedGLMFence(t *testing.T) {
	raw := "{\njson\n{\n  \"thought\": \"ok\",\n  \"actions\": [\n    {\"name\": \"done\", \"args\": {\"summary\": \"x\", \"candidates\": []}}\n  ]\n}\n```"
	resp, err := planner.ParseLLMResponse(raw)
	if err != nil {
		t.Fatalf("unexpected: %v (raw=%q)", err, raw)
	}
	if resp.Thought != "ok" {
		t.Errorf("Thought = %q", resp.Thought)
	}
	if resp.Actions[0].Name != "done" {
		t.Errorf("Name = %q", resp.Actions[0].Name)
	}
}
