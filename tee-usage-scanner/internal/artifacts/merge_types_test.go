package artifacts

import (
	"encoding/json"
	"testing"
)

func TestProjectUnderstandingContractsRoundTrip(t *testing.T) {
	model := ArchitectureModel{
		SchemaVersion: "teecheck.architecture.v1",
		RunID:         "run-1",
		Repo:          RepoRef{URL: "repo", Commit: "abc"},
		Assets: []ArchitectureElement{{
			ID: "asset-wallet-state", Kind: "asset", Name: "WalletState",
			State:    EvidenceObserved,
			Evidence: []EvidenceReference{{Kind: "source", File: "state.rs", StartLine: 10, EndLine: 20}},
		}},
	}
	data, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	var got ArchitectureModel
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Assets[0].State != EvidenceObserved || got.Assets[0].Evidence[0].File != "state.rs" {
		t.Fatalf("round trip changed model: %+v", got)
	}
}

func TestToolFactAndAgentAssessmentStaySeparate(t *testing.T) {
	fact := ToolFact{
		SchemaVersion: "teecheck.tool_fact.v1",
		FactID:        "fact-1", Tool: "trustir", Operation: "trace_flow",
		RepoCommit: "abc", Status: "success",
		Result: json.RawMessage(`{"violation":true}`),
	}
	finding := UnifiedFindingV3{
		SchemaVersion: "teecheck.finding.v3",
		FindingID:     "finding-1", Summary: "rollback candidate",
		ToolFactRefs:    []string{fact.FactID},
		AgentAssessment: AgentAssessment{Status: "contested", Confidence: "medium"},
	}
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["tool_facts"]; ok {
		t.Fatal("finding must reference immutable tool facts, not embed/rewrite them")
	}
	if refs, ok := raw["tool_fact_refs"].([]any); !ok || len(refs) != 1 {
		t.Fatalf("tool fact refs missing: %s", data)
	}
}
