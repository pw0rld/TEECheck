package artifacts

// Per-schema round-trip and rejection tests for the seven §9 contracts whose
// Go types live in this package (the eighth, TWEPlaybook, is tested in
// internal/twecontext since its type lives there). For each schema:
//   - a valid Go value must marshal to JSON the schema accepts;
//   - a copy missing a required field must be rejected;
//   - at least one enum/pattern violation named in the PR-01 brief must be
//     rejected.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

func TestSchemaArchitectureV1(t *testing.T) {
	model := ArchitectureModel{
		SchemaVersion: SchemaVersionArchitectureV1,
		RunID:         "run-1",
		Repo:          RepoRef{URL: "repo", Commit: "abc"},
		Assets: []ArchitectureElement{{
			ID: "asset-wallet-state", Kind: "asset", Name: "WalletState",
			State:    EvidenceObserved,
			Evidence: []EvidenceReference{{Kind: "source", File: "state.rs", StartLine: 10, EndLine: 20}},
		}},
		Boundaries: []ArchitectureRelation{{
			ID: "boundary-1", Kind: "trust_boundary", From: "party-host", To: "asset-wallet-state",
			State: EvidenceInferred,
		}},
	}
	data := marshalJSON(t, model)
	if err := schema.Validate(schema.ArchitectureV1, data); err != nil {
		t.Fatalf("valid ArchitectureModel rejected: %v", err)
	}

	if err := schema.Validate(schema.ArchitectureV1, withoutField(t, data, "run_id")); err == nil {
		t.Fatal("expected missing run_id to be rejected")
	}
	// EvidenceState enum: observed|inferred|documented|unknown.
	bad := withField(t, data, "guessed", "assets", 0, "state")
	if err := schema.Validate(schema.ArchitectureV1, bad); err == nil {
		t.Fatal("expected an out-of-enum element state to be rejected")
	}
	// The same enum on a relation, not just an element.
	badRelation := withField(t, data, "unverified", "boundaries", 0, "state")
	if err := schema.Validate(schema.ArchitectureV1, badRelation); err == nil {
		t.Fatal("expected an out-of-enum relation state to be rejected")
	}
}

func TestSchemaProjectInvariantV1(t *testing.T) {
	invariant := ProjectInvariant{
		SchemaVersion:      SchemaVersionProjectInvariantV1,
		InvariantID:        "INV-STATE-001",
		Statement:          "Restored WalletState must be checked against a non-replayable freshness anchor before SignTransaction",
		RelatedTWEs:        []string{"TWE-STATE-001"},
		Entrypoints:        []string{"restore_wallet"},
		AuthorityPoints:    []string{"sign_transaction"},
		RequiredProperties: []string{"state_freshness", "version_continuity"},
		ExpectedDefenses:   []string{"external_epoch", "monotonic_counter"},
		VerificationPlan:   []string{},
		Status:             "proposed",
	}
	data := marshalJSON(t, invariant)
	if err := schema.Validate(schema.ProjectInvariantV1, data); err != nil {
		t.Fatalf("valid ProjectInvariant rejected: %v", err)
	}

	// classification is optional and additive: absent validates (the base
	// `data` above omits it), and catalog_gap validates when present.
	withClass := invariant
	withClass.Classification = "catalog_gap"
	if err := schema.Validate(schema.ProjectInvariantV1, marshalJSON(t, withClass)); err != nil {
		t.Fatalf("ProjectInvariant with classification=catalog_gap rejected: %v", err)
	}
	badClass := invariant
	badClass.Classification = "made_up_class"
	if err := schema.Validate(schema.ProjectInvariantV1, marshalJSON(t, badClass)); err == nil {
		t.Fatal("expected an out-of-enum classification to be rejected")
	}

	if err := schema.Validate(schema.ProjectInvariantV1, withoutField(t, data, "statement")); err == nil {
		t.Fatal("expected missing statement to be rejected")
	}
	// related_twes has minItems:1 — an empty-but-present array must fail.
	empty := withField(t, data, []any{}, "related_twes")
	if err := schema.Validate(schema.ProjectInvariantV1, empty); err == nil {
		t.Fatal("expected empty related_twes to be rejected (minItems: 1)")
	}
	// status enum: proposed|grounded|satisfied|violated_candidate|unresolved|not_applicable.
	badStatus := withField(t, data, "made_up_status", "status")
	if err := schema.Validate(schema.ProjectInvariantV1, badStatus); err == nil {
		t.Fatal("expected an out-of-enum status to be rejected")
	}
	// "unresolved" itself must be a *valid* status — it is the field that
	// tracks an invariant that could not be verified, not an error state.
	unresolved := withField(t, data, "unresolved", "status")
	if err := schema.Validate(schema.ProjectInvariantV1, unresolved); err != nil {
		t.Fatalf("status %q must be accepted: %v", "unresolved", err)
	}
}

func TestSchemaTWEKnowledgeManifestV1(t *testing.T) {
	manifest := TWEKnowledgeManifest{
		SchemaVersion:  SchemaVersionTWEKnowledgeManifestV1,
		CatalogVersion: "teecheck.twe_playbook.v1",
		CatalogSHA256:  "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
		ContextSHA256:  "d4c3b2a1d4c3b2a1d4c3b2a1d4c3b2a1d4c3b2a1d4c3b2a1d4c3b2a1d4c3b2a1",
		TWEIDs:         []string{"TWE-STATE-001"},
	}
	data := marshalJSON(t, manifest)
	if err := schema.Validate(schema.TWEKnowledgeManifestV1, data); err != nil {
		t.Fatalf("valid TWEKnowledgeManifest rejected: %v", err)
	}

	// The compiled context size must survive into the persisted artifact:
	// §11.1's budget fails compilation instead of truncating, so this is the
	// only record of how close a run came to the ceiling.
	withEstimate := manifest
	withEstimate.ContextTokenEstimate = 720
	sized := marshalJSON(t, withEstimate)
	if err := schema.Validate(schema.TWEKnowledgeManifestV1, sized); err != nil {
		t.Fatalf("manifest carrying context_token_estimate rejected: %v", err)
	}
	if !bytes.Contains(sized, []byte(`"context_token_estimate":720`)) {
		t.Fatalf("context_token_estimate missing from persisted manifest: %s", sized)
	}
	// It stays optional: manifests written before the field existed still load.
	if err := schema.Validate(schema.TWEKnowledgeManifestV1, withoutField(t, sized, "context_token_estimate")); err != nil {
		t.Fatalf("manifest without context_token_estimate must still validate: %v", err)
	}

	if err := schema.Validate(schema.TWEKnowledgeManifestV1, withoutField(t, data, "catalog_sha256")); err == nil {
		t.Fatal("expected missing catalog_sha256 to be rejected")
	}
	// catalog_sha256 pattern: ^[a-f0-9]{64}$.
	badHash := withField(t, data, "not-a-hash", "catalog_sha256")
	if err := schema.Validate(schema.TWEKnowledgeManifestV1, badHash); err == nil {
		t.Fatal("expected a malformed catalog_sha256 to be rejected")
	}
	// twe_ids item pattern: ^TWE-[A-Z0-9-]+$.
	badID := withField(t, data, []any{"not-a-twe-id"}, "twe_ids")
	if err := schema.Validate(schema.TWEKnowledgeManifestV1, badID); err == nil {
		t.Fatal("expected a malformed twe id to be rejected")
	}
}

func TestSchemaToolFactV1(t *testing.T) {
	fact := ToolFact{
		SchemaVersion: SchemaVersionToolFactV1,
		RequestID:     "req-1",
		FactID:        "fact-1",
		Tool:          "trustir",
		ToolVersion:   "0.3.0",
		Operation:     "trace_flow",
		RepoCommit:    "abc123",
		Status:        "success",
		Locations:     []ToolLocation{{Path: "src/state.rs", StartLine: 42}},
		Result:        json.RawMessage(`{"violation":true}`),
	}
	data := marshalJSON(t, fact)
	if err := schema.Validate(schema.TrustIRToolV1, data); err != nil {
		t.Fatalf("valid ToolFact rejected: %v", err)
	}

	if err := schema.Validate(schema.TrustIRToolV1, withoutField(t, data, "repo_commit")); err == nil {
		t.Fatal("expected missing repo_commit to be rejected")
	}
	// status enum: success|error|unsupported|unresolved.
	badStatus := withField(t, data, "pending", "status")
	if err := schema.Validate(schema.TrustIRToolV1, badStatus); err == nil {
		t.Fatal("expected an out-of-enum status to be rejected")
	}

	// "error" and "unresolved" are first-class statuses, and error/
	// coverage_gaps/truncated must be reachable, not merely allowed by
	// the schema in the abstract.
	errored := ToolFact{
		SchemaVersion: SchemaVersionToolFactV1, RequestID: "req-2", FactID: "fact-2",
		Tool: "trustir", Operation: "trace_flow", RepoCommit: "abc123",
		Status: "error", Error: "query timed out after 30s",
	}
	if err := schema.Validate(schema.TrustIRToolV1, marshalJSON(t, errored)); err != nil {
		t.Fatalf("status=error with an Error message must validate: %v", err)
	}
	unresolved := ToolFact{
		SchemaVersion: SchemaVersionToolFactV1, RequestID: "req-3", FactID: "fact-3",
		Tool: "trustir", Operation: "trace_flow", RepoCommit: "abc123",
		Status: "unresolved", CoverageGaps: []string{"call graph did not resolve across the FFI boundary"},
		Truncated: true,
	}
	if err := schema.Validate(schema.TrustIRToolV1, marshalJSON(t, unresolved)); err != nil {
		t.Fatalf("status=unresolved with coverage_gaps/truncated must validate: %v", err)
	}
}

func TestSchemaTWEInvestigationV1(t *testing.T) {
	investigation := TWEInvestigation{
		SchemaVersion:   SchemaVersionTWEInvestigationV1,
		InvestigationID: "inv-1",
		TWEIDs:          []string{"TWE-STATE-001"},
		InvariantIDs:    []string{"INV-STATE-001"},
		Classification:  "standard",
		CoverageGaps:    []string{"no evidence of restore_wallet's caller"},
		MissingRoles:    []string{"external_epoch_source"},
	}
	data := marshalJSON(t, investigation)
	if err := schema.Validate(schema.TWEInvestigationV1, data); err != nil {
		t.Fatalf("valid TWEInvestigation rejected: %v", err)
	}

	if err := schema.Validate(schema.TWEInvestigationV1, withoutField(t, data, "classification")); err == nil {
		t.Fatal("expected missing classification to be rejected")
	}
	// twe_ids has minItems:1 — an empty-but-present array must fail.
	empty := withField(t, data, []any{}, "twe_ids")
	if err := schema.Validate(schema.TWEInvestigationV1, empty); err == nil {
		t.Fatal("expected empty twe_ids to be rejected (minItems: 1)")
	}
	// classification enum: standard|variant|composition|catalog_gap.
	badClass := withField(t, data, "unclassified", "classification")
	if err := schema.Validate(schema.TWEInvestigationV1, badClass); err == nil {
		t.Fatal("expected an out-of-enum classification to be rejected")
	}
}

func TestSchemaFindingV3(t *testing.T) {
	finding := UnifiedFindingV3{
		SchemaVersion:  SchemaVersionFindingV3,
		FindingID:      "finding-1",
		RelatedTWEs:    []string{"TWE-STATE-001"},
		Classification: "standard",
		Summary:        "rollback candidate",
		ToolFactRefs:   []string{"fact-1"},
		AgentAssessment: AgentAssessment{
			Status: "contested", Severity: "high", Confidence: "medium",
		},
		CoverageGaps: []string{"no evidence external_epoch_source is checked before sign_transaction"},
	}
	data := marshalJSON(t, finding)
	if err := schema.Validate(schema.FindingV3, data); err != nil {
		t.Fatalf("valid UnifiedFindingV3 rejected: %v", err)
	}

	if err := schema.Validate(schema.FindingV3, withoutField(t, data, "summary")); err == nil {
		t.Fatal("expected missing summary to be rejected")
	}
	if err := schema.Validate(schema.FindingV3, withoutField(t, data, "agent_assessment")); err == nil {
		t.Fatal("expected missing agent_assessment to be rejected")
	}
	// agent_assessment.status enum: supported|contested|needs_context|rejected.
	badStatus := withField(t, data, "maybe", "agent_assessment", "status")
	if err := schema.Validate(schema.FindingV3, badStatus); err == nil {
		t.Fatal("expected an out-of-enum agent_assessment.status to be rejected")
	}

	withVerdict := finding
	withVerdict.HumanVerdict = &HumanVerdict{Verdict: "true_positive", ReasonCode: "confirmed_exploit"}
	if err := schema.Validate(schema.FindingV3, marshalJSON(t, withVerdict)); err != nil {
		t.Fatalf("valid human_verdict rejected: %v", err)
	}
	// human_verdict, when present, requires its own "verdict" field.
	badVerdict := withField(t, data, map[string]any{"reason_code": "fp_test_only"}, "human_verdict")
	if err := schema.Validate(schema.FindingV3, badVerdict); err == nil {
		t.Fatal("expected human_verdict without verdict to be rejected")
	}
}
