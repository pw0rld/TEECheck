package planner

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func leadActionFixture(t *testing.T) (RunConfig, *PlannerState, ObservationSet) {
	t.Helper()
	cfg := RunConfig{RunID: "run-1", SampleIndex: 2, RunDir: t.TempDir(), Profile: PromptProfile{Commit: "revision"}}
	state := NewState(cfg.RunID)
	state.AuditLeads = []artifacts.AuditLead{{SchemaVersion: "teecheck.audit_lead.v1", RunID: cfg.RunID, SampleIndex: 2, LeadID: "lead-s2-001", State: artifacts.LeadStateOpen, OpenedAtRound: 1, SecurityQuestion: "Does the observed check enforce the input requirement?", TargetSymbolIDs: []artifacts.SymbolID{"input.c::verify"}, Reason: []string{"The function decides input validity."}, ReasonFactRefs: []string{"obs:2:1:0:read"}}}
	obs := ObservationSet{}
	obs.Record("obs:2:1:0:read", true)
	obs.Record("obs:2:2:0:failed", false)
	return cfg, state, obs
}

func leadArgs(t *testing.T, args any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLeadActionsUpdateAndClosePreserveEvidence(t *testing.T) {
	cfg, state, observed := leadActionFixture(t)
	args := leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "add_notes": []any{map[string]any{"fact_ref": "obs:2:1:0:read", "summary": "The guard depends on the supplied value."}}, "add_ruled_out": []string{"No caller-side constant prevents this input."}})
	result := updateLead(cfg, state, observed, nil, args, 6)
	if !result.OK {
		t.Fatal(result.Error)
	}
	lead := state.AuditLeads[0]
	if lead.State != artifacts.LeadStateExpanded || len(lead.EvidenceNotes) != 1 || lead.EvidenceNotes[0].AddedAtRound != 6 || len(lead.RuledOut) != 1 {
		t.Fatalf("wrong expanded lead: %+v", lead)
	}
	// Repeating a note does not duplicate it or rewrite its original round.
	if result = updateLead(cfg, state, observed, nil, args, 7); !result.OK {
		t.Fatal(result.Error)
	}
	if len(state.AuditLeads[0].EvidenceNotes) != 1 || state.AuditLeads[0].EvidenceNotes[0].AddedAtRound != 6 {
		t.Fatal("repeated note changed evidence history")
	}
	// A later note cannot regress an already formalized lead to expanded.
	state.AuditLeads[0].State = artifacts.LeadStateFormalized
	state.AuditLeads[0].ContractIDs = []string{"contract-1"}
	if result = updateLead(cfg, state, observed, nil, args, 8); !result.OK {
		t.Fatal(result.Error)
	}
	if state.AuditLeads[0].State != artifacts.LeadStateFormalized {
		t.Fatal("update regressed formalized state")
	}
	result = closeLead(cfg, state, observed, nil, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "reason": "The independent checks cover the stated obligation.", "fact_refs": []string{"obs:2:1:0:read"}}), 9)
	if !result.OK {
		t.Fatal(result.Error)
	}
	lead = state.AuditLeads[0]
	if lead.State != artifacts.LeadStateClosed || len(lead.CloseFactRefs) != 1 || lead.CloseReason == "" || len(lead.ContractIDs) != 1 || len(lead.EvidenceNotes) != 1 {
		t.Fatalf("closing lost evidence: %+v", lead)
	}
	before := cloneLead(lead)
	if result = updateLead(cfg, state, observed, nil, args, 10); result.OK || !strings.Contains(result.Error, "closed") {
		t.Fatalf("closed lead updated: %+v", result)
	}
	if !reflect.DeepEqual(before, state.AuditLeads[0]) {
		t.Fatal("rejected update changed closed lead")
	}
	f, err := os.Open(runfs.AuditLeadsPath(cfg.RunDir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var latest artifacts.AuditLead
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if err := json.Unmarshal(scan.Bytes(), &latest); err != nil {
			t.Fatal(err)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lead, latest) {
		t.Fatalf("latest persisted revision differs: %+v", latest)
	}
}

func TestLeadActionsInvalidUpdateCannotMutateState(t *testing.T) {
	for _, mode := range []string{"unknown lead", "other sample", "other run", "failed observation", "unobserved ref", "empty note", "long note", "partial update", "ruled out without evidence", "taint unsupported"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, obs := leadActionFixture(t)
			id, ref, summary := "lead-s2-001", "obs:2:1:0:read", "Observed guarded input."
			args := map[string]any{}
			switch mode {
			case "unknown lead":
				id = "missing"
			case "other sample":
				state.AuditLeads[0].SampleIndex = 1
			case "other run":
				state.AuditLeads[0].RunID = "old-run"
			case "failed observation":
				ref = "obs:2:2:0:failed"
			case "unobserved ref":
				ref = "obs:1:1:0:read"
			case "empty note":
				summary = " "
			case "long note":
				summary = strings.Repeat("界", 81)
			case "ruled out without evidence":
				args["add_ruled_out"] = []string{"Check is sufficient."}
			case "taint unsupported":
				args["add_taint_fact_refs"] = []string{"fact-1"}
			}
			args["lead_id"] = id
			if len(args) == 1 {
				notes := []any{map[string]any{"fact_ref": ref, "summary": summary}}
				if mode == "partial update" {
					notes = append(notes, map[string]any{"fact_ref": "unobserved", "summary": "A second invalid note."})
				}
				args["add_notes"] = notes
			}
			before, _ := json.Marshal(state)
			result := updateLead(cfg, state, obs, nil, leadArgs(t, args), 4)
			after, _ := json.Marshal(state)
			if result.OK || string(before) != string(after) {
				t.Fatalf("invalid update accepted or mutated state: %+v", result)
			}
			if _, err := os.Stat(runfs.AuditLeadsPath(cfg.RunDir)); !os.IsNotExist(err) {
				t.Fatalf("invalid update persisted: %v", err)
			}
		})
	}
}

func TestLeadActionsClosingRequiresEvidence(t *testing.T) {
	for _, args := range []map[string]any{
		{"lead_id": "lead-s2-001", "reason": " ", "fact_refs": []string{"obs:2:1:0:read"}},
		{"lead_id": "lead-s2-001", "reason": "Done", "fact_refs": []string{}},
		{"lead_id": "lead-s2-001", "reason": "Done", "fact_refs": []string{"obs:1:1:0:read"}},
	} {
		cfg, state, obs := leadActionFixture(t)
		result := closeLead(cfg, state, obs, nil, leadArgs(t, args), 8)
		if result.OK || state.AuditLeads[0].State != artifacts.LeadStateOpen {
			t.Fatalf("invalid close accepted: %+v", result)
		}
	}
}

func TestLeadActionPersistenceFailureLeavesStateUnchanged(t *testing.T) {
	cfg, state, obs := leadActionFixture(t)
	if err := os.WriteFile(filepath.Join(cfg.RunDir, "04_planner"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	result := updateLead(cfg, state, obs, nil, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "add_notes": []any{map[string]any{"fact_ref": "obs:2:1:0:read", "summary": "A valid note."}}}), 4)
	if result.OK || state.AuditLeads[0].State != artifacts.LeadStateOpen || len(state.AuditLeads[0].EvidenceNotes) != 0 {
		t.Fatalf("failed persistence changed state: %+v", result)
	}
}

func TestLeadNotesRequireExecutedSuccessfulInScopeToolFact(t *testing.T) {
	for _, mode := range []string{"path", "fact id", "relative run path", "run-relative fact", "not executed", "failed status", "wrong commit"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, obs := leadActionFixture(t)
			if mode == "relative run path" {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				cfg.RunDir, err = filepath.Rel(cwd, cfg.RunDir)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := runfs.WriteJSON(runfs.ManifestPath(cfg.RunDir), artifacts.Manifest{RunID: cfg.RunID, Commit: "revision"}); err != nil {
				t.Fatal(err)
			}
			fact := artifacts.ToolFact{SchemaVersion: "teecheck.trustir_result.v1", RequestID: "query-1", FactID: "fact-1", Tool: "codeql", Operation: "query", RepoCommit: "revision", Status: "success"}
			if mode == "failed status" {
				fact.Status = "error"
			}
			if mode == "wrong commit" {
				fact.RepoCommit = "another-revision"
			}
			path := filepath.Join(runfs.ToolFactsDir(cfg.RunDir), "fact-1.json")
			if err := runfs.WriteJSON(path, fact); err != nil {
				t.Fatal(err)
			}
			ref, executed := path, []string{path}
			if mode == "run-relative fact" {
				rel, err := filepath.Rel(cfg.RunDir, path)
				if err != nil {
					t.Fatal(err)
				}
				ref, executed = rel, []string{rel}
			}
			if mode == "fact id" {
				ref = "fact-1"
			}
			if mode == "not executed" {
				executed = nil
			}
			result := updateLead(cfg, state, obs, executed, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "add_notes": []any{map[string]any{"fact_ref": ref, "summary": "The query recorded an observed relationship."}}}), 4)
			want := mode == "path" || mode == "fact id" || mode == "relative run path" || mode == "run-relative fact"
			if result.OK != want {
				t.Fatalf("success=%v want=%v error=%s", result.OK, want, result.Error)
			}
		})
	}
}
