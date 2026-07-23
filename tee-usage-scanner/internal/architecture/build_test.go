package architecture

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// ─── BuildHeuristic: conservative by construction ───────────────────────

func TestBuildHeuristic_ManifestsBecomeObservedComponents(t *testing.T) {
	in := Input{
		Profile: artifacts.ProjectProfileV2{
			Manifests: []artifacts.ProfileSignal{{
				ID: "manifest:enclave.config.xml", Kind: "manifest", Name: "SGX enclave configuration",
				Scope:    "enclave.config.xml",
				Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: "enclave.config.xml"}},
			}},
		},
	}
	model := BuildHeuristic(in)
	if len(model.Components) != 1 {
		t.Fatalf("Components = %d, want 1", len(model.Components))
	}
	if model.Components[0].State != artifacts.EvidenceObserved {
		t.Errorf("state = %q, want observed (manifest existence is a legitimate observed fact)", model.Components[0].State)
	}
}

// §3.4: "发现 validator 关键词只能产生 candidate_role,不能断言该组件就是安全
// 架构中的 validator" — the heuristic path must not promote candidate role/
// artifact/boundary/state signals to any observed bucket.
func TestBuildHeuristic_CandidateSignalsBecomeUnknownsNotObservedFacts(t *testing.T) {
	in := Input{
		Profile: artifacts.ProjectProfileV2{
			CandidateRoles: []artifacts.ProfileSignal{{
				ID: "role:validator-consensus", Kind: "candidate_role", Name: "Validator or consensus",
				Evidence: []artifacts.EvidenceReference{{Kind: "code_or_config", File: "src/lib.rs", StartLine: 10, EndLine: 10}},
			}},
			TrustArtifacts: []artifacts.ProfileSignal{{ID: "artifact:attestation", Kind: "trust_artifact", Name: "Attestation artifacts"}},
		},
	}
	model := BuildHeuristic(in)
	if len(model.Roles) != 0 {
		t.Fatalf("Roles = %+v, want none — candidate_role must not become an asserted role", model.Roles)
	}
	if len(model.Assets) != 0 {
		t.Fatalf("Assets = %+v, want none", model.Assets)
	}
	if len(model.Unknowns) != 2 {
		t.Fatalf("Unknowns = %d, want 2 (one per candidate signal)", len(model.Unknowns))
	}
	for _, u := range model.Unknowns {
		if u.State != artifacts.EvidenceUnknown {
			t.Errorf("unknown entry %s has state %q", u.ID, u.State)
		}
	}
}

func TestBuildHeuristic_CoverageWarningsSurfaced(t *testing.T) {
	in := Input{Profile: artifacts.ProjectProfileV2{CoverageWarnings: []string{"content scan skipped 3 files larger than 2097152 bytes"}}}
	model := BuildHeuristic(in)
	found := false
	for _, u := range model.Unknowns {
		if strings.Contains(u.Description, "skipped 3 files") {
			found = true
		}
	}
	if !found {
		t.Errorf("coverage warnings not surfaced into Unknowns: %+v", model.Unknowns)
	}
}

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

func TestBuild_DispatchesByMode(t *testing.T) {
	in := Input{Profile: artifacts.ProjectProfileV2{Manifests: []artifacts.ProfileSignal{{ID: "manifest:x", Kind: "manifest", Name: "X"}}}}
	model, err := Build(context.Background(), nil, "heuristic", in, 0)
	if err != nil {
		t.Fatalf("heuristic dispatch: %v", err)
	}
	if len(model.Components) != 1 {
		t.Fatalf("heuristic dispatch did not run BuildHeuristic: %+v", model)
	}
}
