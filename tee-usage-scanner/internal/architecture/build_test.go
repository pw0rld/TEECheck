package architecture

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// ─── BuildLLM: stub client, no live model (per PR-04's testing constraint) ─

type stubClient struct {
	responseJSON string
	gotRequest   *llm.GenerateRequest
	err          error
}

func (s *stubClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequest = &req
	if s.err != nil {
		return llm.GenerateResponse{}, s.err
	}
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

func TestBuildLLM_ParsesWireModelDirectly(t *testing.T) {
	resp := map[string]any{
		"parties": []map[string]any{},
		"components": []map[string]any{
			{"id": "component-enclave", "kind": "component", "name": "Enclave", "state": "observed",
				"evidence": []map[string]any{{"kind": "source", "file": "src/lib.rs", "start_line": 1, "end_line": 5, "note": "Enclave"}}},
		},
		"roles": []map[string]any{}, "assets": []map[string]any{}, "trust_zones": []map[string]any{},
		"entrypoints": []map[string]any{}, "boundaries": []map[string]any{}, "data_flows": []map[string]any{},
		"state_lifecycles": []map[string]any{}, "trust_assumptions": []map[string]any{},
		"deployment_assumptions": []map[string]any{},
		"unknowns": []map[string]any{
			{"id": "unk-1", "kind": "role", "name": "MysteryComponent", "state": "unknown"},
		},
	}
	data, _ := json.Marshal(resp)
	stub := &stubClient{responseJSON: string(data)}

	model, err := BuildLLM(context.Background(), stub, Input{TWEContext: "TWE-STATE-001..."}, 0.2)
	if err != nil {
		t.Fatalf("BuildLLM: %v", err)
	}
	if len(model.Components) != 1 || model.Components[0].Name != "Enclave" {
		t.Fatalf("components = %+v", model.Components)
	}
	if len(model.Unknowns) != 1 || model.Unknowns[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("unknowns = %+v", model.Unknowns)
	}
	if !strings.Contains(stub.gotRequest.Messages[0].Content, "TWE-STATE-001") {
		t.Error("TWE prior knowledge context was not included in the prompt")
	}
	if !strings.Contains(stub.gotRequest.SystemPrompt, "unknown") {
		t.Error("system prompt does not mention the unknown state discipline")
	}
}

func TestBuildLLM_NilClientErrors(t *testing.T) {
	if _, err := BuildLLM(context.Background(), nil, Input{}, 0); err == nil {
		t.Fatal("expected an error for a nil client")
	}
}
