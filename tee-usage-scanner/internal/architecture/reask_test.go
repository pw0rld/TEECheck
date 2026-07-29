package architecture

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// The array-wrapped reply that killed a live glm-5.2 run. Every LLM-backed
// agent must survive exactly one of these; a helper wired into only some of
// the call sites is the defect this project keeps hitting.
const arrayWrappedArchitecture = `[["components"], {"components": [{"id": "component-enclave", "kind": "component", "name": "Enclave", "state": "observed"}]}]`

const cleanArchitecture = `{"components": [{"id": "component-enclave", "kind": "component", "name": "RecoveredEnclave", "state": "observed"}]}`

func TestBuildLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedArchitecture, cleanArchitecture}}

	model, err := BuildLLM(context.Background(), fake, Input{TWEContext: "TWE-STATE-001"}, 0.2)
	if err != nil {
		t.Fatalf("BuildLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective re-ask)", len(fake.Calls))
	}
	if len(model.Components) != 1 || model.Components[0].Name != "RecoveredEnclave" {
		t.Fatalf("components = %+v, want the re-asked reply's component", model.Components)
	}
}

func TestBuildLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedArchitecture, `["still an array"]`}, Default: cleanArchitecture}

	if _, err := BuildLLM(context.Background(), fake, Input{}, 0.2); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
