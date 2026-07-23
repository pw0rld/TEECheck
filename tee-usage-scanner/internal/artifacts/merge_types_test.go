package artifacts

import (
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

func TestProjectUnderstandingContractsRoundTrip(t *testing.T) {
	model := ArchitectureModel{
		SchemaVersion: SchemaVersionArchitectureV1,
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
		SchemaVersion: SchemaVersionToolFactV1,
		RequestID:     "req-1",
		FactID:        "fact-1", Tool: "trustir", Operation: "trace_flow",
		RepoCommit: "abc", Status: "success",
		Result: json.RawMessage(`{"violation":true}`),
	}
	finding := UnifiedFindingV3{
		SchemaVersion: SchemaVersionFindingV3,
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

// EvidenceReference.CitedBytes is the PR-04 bridge to internal/citations —
// see internal/architecture's package doc comment for the full design
// rationale. These are the pure conversion-shape tests; the actual
// resolve/downgrade behavior built on top of it is tested in
// internal/architecture and internal/invariants.
func TestEvidenceReference_CitedBytes(t *testing.T) {
	ref := EvidenceReference{Kind: "source", File: "src/state.rs", StartLine: 10, EndLine: 20}
	got := ref.CitedBytes()
	want := citations.CitedBytes{File: "src/state.rs", StartLine: 10, EndLine: 20}
	if got != want {
		t.Fatalf("CitedBytes() = %+v, want %+v", got, want)
	}
}

// A citation naming one line only (EndLine omitted, the JSON zero value)
// must not be rejected purely for the redundant end_line being absent.
func TestEvidenceReference_CitedBytes_NormalizesMissingEndLine(t *testing.T) {
	ref := EvidenceReference{Kind: "source", File: "src/state.rs", StartLine: 10}
	got := ref.CitedBytes()
	if got.EndLine != 10 {
		t.Fatalf("EndLine = %d, want 10 (normalized to StartLine)", got.EndLine)
	}
	if !got.Valid() {
		t.Fatal("normalized single-line citation must be Valid()")
	}
}

// Evidence with no File (artifact_ref-only, pointing at a persisted tool
// result rather than source bytes) must not be Valid() — callers must
// treat it as unresolvable-by-this-bridge, not silently pass.
func TestEvidenceReference_CitedBytes_ArtifactRefOnlyIsNotValid(t *testing.T) {
	ref := EvidenceReference{Kind: "tool_result", ArtifactRef: "case-001/hypothesis-001.json"}
	if ref.CitedBytes().Valid() {
		t.Fatal("an artifact_ref-only evidence reference must not resolve as a byte citation")
	}
}
