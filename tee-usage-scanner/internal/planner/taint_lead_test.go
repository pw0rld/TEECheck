package planner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/taint"
)

func taintLeadFixture(t *testing.T) (RunConfig, *PlannerState, ObservationSet, artifacts.ToolFact, string) {
	t.Helper()
	cfg, state, observed := leadActionFixture(t)
	cfg.RepoRoot = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "input.c"), []byte("int verify(int value) { return value; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("https://example.test/project", "revision", cfg.RepoRoot)
	cfg.Profile.RepoURL, cfg.Profile.Commit = scope.RepoURL, scope.Commit
	if err := runfs.WriteJSON(runfs.ManifestPath(cfg.RunDir), artifacts.Manifest{RunID: cfg.RunID, RepoURL: scope.RepoURL, Commit: scope.Commit, LocalPath: cfg.RepoRoot, Scope: scope}); err != nil {
		t.Fatal(err)
	}
	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		RequestID:     "trace-request", FactID: "taint-" + strings.Repeat("a", 64),
		Tool: "codeql-cpp-taint", Operation: taint.Operation, RepoCommit: scope.Commit,
		ArgumentsSHA256: strings.Repeat("a", 64), Scope: &scope, Status: "success",
		Result:       json.RawMessage(`{"total_paths":1,"barriers_applied":[]}`),
		CoverageGaps: []string{"May-flow witness only; this does not establish a vulnerability or safety."},
	}
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	path := filepath.Join(runfs.TrustIRToolFactsDir(cfg.RunDir), "taint-test.json")
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	return cfg, state, observed, fact, path
}

func TestUpdateLeadAcceptsExecutedTaintEvidence(t *testing.T) {
	for _, mode := range []string{"path", "fact id", "zero paths"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, observed, fact, path := taintLeadFixture(t)
			ref := path
			if mode == "fact id" {
				ref = fact.FactID
			}
			if mode == "zero paths" {
				fact.Result = json.RawMessage(`{"total_paths":0,"barriers_applied":["check_input"]}`)
				fact.CoverageGaps = []string{taint.ZeroPathNotice}
				fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
				if err := runfs.WriteJSON(path, fact); err != nil {
					t.Fatal(err)
				}
			}
			args := leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "add_taint_fact_refs": []string{ref, ref}})
			result := updateLead(cfg, state, observed, []string{path}, args, 5)
			if !result.OK {
				t.Fatalf("valid executed taint fact rejected: %s", result.Error)
			}
			lead := state.AuditLeads[0]
			if lead.State != artifacts.LeadStateExpanded || len(lead.TaintFactRefs) != 1 || len(state.Contracts) != 0 {
				t.Fatalf("wrong evidence/state update: lead=%+v contracts=%+v", lead, state.Contracts)
			}
			persisted, err := contractLeads(cfg)
			if err != nil || !reflect.DeepEqual(persisted[lead.LeadID], lead) {
				t.Fatalf("taint evidence did not persist: %v %+v", err, persisted)
			}
			// Reusing immutable evidence must not duplicate it or manufacture
			// an assessment, including when a query found no paths.
			result = updateLead(cfg, state, observed, []string{path}, args, 6)
			if !result.OK || len(state.AuditLeads[0].TaintFactRefs) != 1 || len(state.Contracts) != 0 {
				t.Fatalf("repeated evidence changed semantics: %+v", result)
			}
		})
	}
}

func TestUpdateLeadRejectsInvalidTaintEvidenceWithoutMutation(t *testing.T) {
	for _, mode := range []string{"wrong operation", "another sample", "tampered content", "wrong repository", "wrong commit", "wrong scope hash", "missing scope", "missing digest", "failed query", "partial batch"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, observed, fact, path := taintLeadFixture(t)
			executed := []string{path}
			refs := []string{path}
			rehash := true
			switch mode {
			case "wrong operation":
				fact.Operation = "cpp.other.query"
			case "another sample":
				executed = nil
			case "tampered content":
				fact.Result = json.RawMessage(`{"total_paths":999}`)
				rehash = false
			case "wrong repository":
				fact.Scope.RepoURL = "https://example.test/other"
			case "wrong commit":
				fact.Scope.Commit = "other-revision"
			case "wrong scope hash":
				fact.Scope.Hash = "other-hash"
			case "missing scope":
				fact.Scope = nil
			case "missing digest":
				fact.ContentSHA256 = ""
				rehash = false
			case "failed query":
				fact.Status = "error"
			case "partial batch":
				refs = append(refs, "unexecuted-taint-fact")
			}
			if rehash {
				fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			}
			if err := runfs.WriteJSON(path, fact); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(state)
			result := updateLead(cfg, state, observed, executed, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "add_taint_fact_refs": refs}), 5)
			after, _ := json.Marshal(state)
			if result.OK || string(before) != string(after) {
				t.Fatalf("invalid taint evidence accepted or partially mutated lead: %+v", result)
			}
			if _, err := os.Stat(runfs.AuditLeadsPath(cfg.RunDir)); !os.IsNotExist(err) {
				t.Fatalf("invalid evidence persisted a lead revision: %v", err)
			}
		})
	}
}
