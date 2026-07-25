package invariants

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type stubClient struct {
	responseJSON string
	gotRequest   *llm.GenerateRequest
}

func (s *stubClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequest = &req
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

func TestBuildLLM_ParsesInvariantsAndIgnoresModelDeclaredStatus(t *testing.T) {
	resp := map[string]any{
		"invariants": []map[string]any{
			{
				"invariant_id":      "INV-STATE-001",
				"statement":         "Restored WalletState must be checked against a freshness anchor before SignTransaction",
				"related_twes":      []string{"TWE-STATE-001"},
				"entrypoints":       []string{"restore_wallet"},
				"authority_points":  []string{"sign_transaction"},
				"verification_plan": []string{"trace freshness anchor propagation"},
				// A model that ignores the "always proposed" instruction and
				// tries to assert a stronger status anyway.
				"status": "satisfied",
			},
		},
	}
	data, _ := json.Marshal(resp)
	stub := &stubClient{responseJSON: string(data)}

	got, err := BuildLLM(context.Background(), stub, Input{TWEContext: "TWE-STATE-001..."}, 0.2)
	if err != nil {
		t.Fatalf("BuildLLM: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("invariants = %+v, want 1", got)
	}
	if got[0].Status != "" {
		t.Errorf("wireInvariant has no status field to parse into artifacts.ProjectInvariant; got %q — the model-declared status must never reach the ProjectInvariant value even before EnforceProposedStatus runs", got[0].Status)
	}
	if got[0].InvariantID != "INV-STATE-001" {
		t.Errorf("invariant_id = %q", got[0].InvariantID)
	}
	if !strings.Contains(stub.gotRequest.Messages[0].Content, "TWE-STATE-001") {
		t.Error("TWE prior knowledge not included in prompt")
	}
	if !strings.Contains(stub.gotRequest.SystemPrompt, "proposed") {
		t.Error("system prompt does not explain the proposed-only status rule")
	}
}

func TestBuildLLM_NilClientErrors(t *testing.T) {
	if _, err := BuildLLM(context.Background(), nil, Input{}, 0); err == nil {
		t.Fatal("expected an error for a nil client")
	}
}
