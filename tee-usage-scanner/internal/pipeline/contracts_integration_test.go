package pipeline_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runvalidate"
)

type contractPipelineClient struct {
	role  string
	calls int
}

func (c *contractPipelineClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	if c.role == "planner" {
		switch c.calls {
		case 1:
			return llm.GenerateResponse{Text: `{"actions":[{"name":"get_repository_card","args":{}},{"name":"list_dir","args":{"path":".","depth":1}},{"name":"read_file","args":{"path":"demo.c","start":1,"end":2}}]}`}, nil
		case 2:
			ref := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
			if len(ref) != 2 {
				return llm.GenerateResponse{}, fmt.Errorf("no observation")
			}
			body, _ := json.Marshal(map[string]any{"actions": []any{map[string]any{"name": "open_audit_lead", "args": map[string]any{"security_question": "Does accept check its input?", "target_symbol_ids": []string{"demo.c::accept"}, "reason": []string{"Observed unconditional acceptance"}, "reason_fact_refs": []string{ref[1]}}}}})
			return llm.GenerateResponse{Text: string(body)}, nil
		case 3:
			lead := regexp.MustCompile(`"lead_id"\s*:\s*"([^"]+)"`).FindStringSubmatch(req.Messages[0].Content)
			if len(lead) != 2 {
				return llm.GenerateResponse{}, fmt.Errorf("no lead id in prompt")
			}
			body, _ := json.Marshal(map[string]any{"actions": []any{map[string]any{"name": "done", "args": map[string]any{"summary": "Input contract investigated", "candidates": []any{}, "case_invariants": []any{map[string]any{"lead_ref": lead[1], "subjects": []any{map[string]any{"path": "demo.c", "symbol": "accept"}}, "preconditions": []string{"the argument can be non-positive"}, "required_property": map[string]any{"kind": "input_guard", "statement": "accept rejects non-positive input"}, "security_effect": "input acceptance decision", "verification_queries": []any{}, "related_twes": []string{"TWE-GUARD-001"}}}}}}})
			return llm.GenerateResponse{Text: string(body)}, nil
		}
		return llm.GenerateResponse{}, fmt.Errorf("unexpected planner call")
	}
	id := regexp.MustCompile(`"invariant_id":"([^"]+)"`).FindStringSubmatch(req.Messages[0].Content)
	if len(id) != 2 {
		return llm.GenerateResponse{}, fmt.Errorf("missing contract for %s", c.role)
	}
	body, _ := json.Marshal(artifacts.ContractReview{InvariantID: id[1], Position: "supported", Reason: "accept unconditionally returns one", PreconditionsSatisfied: true, AttackChainComplete: true, Witness: []artifacts.ContractSubject{{Path: "demo.c", Symbol: "accept", StartLine: 1, EndLine: 1}}})
	return llm.GenerateResponse{Text: string(body)}, nil
}

func TestPipeline_ContractDiscoveryReachesIndependentAssessmentAndArbiter(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "demo.c"), []byte("int accept(int value) { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, e, c, v := &contractPipelineClient{role: "planner"}, &contractPipelineClient{role: "expert"}, &contractPipelineClient{role: "challenger"}, &contractPipelineClient{role: "verifier"}
	a := &contractPipelineClient{role: "arbiter"}
	dir, err := pipeline.RunWithClients(config.Config{Command: "run", Target: root, Mode: "llm", Focus: "tee", RunID: "contract-smoke", OutputDir: out, KnowledgeRoot: filepath.Join(out, "knowledge")}, pipeline.RoleClients{Planner: p, Expert: e, Challenger: c, Verifier: v, Arbiter: a})
	if err != nil {
		t.Fatal(err)
	}
	if p.calls != 3 || e.calls != 1 || c.calls != 1 || v.calls != 1 {
		t.Fatalf("unexpected calls: %d %d %d %d", p.calls, e.calls, c.calls, v.calls)
	}
	if a.calls != 0 {
		t.Fatal("contract arbitration should use the validated assessments directly")
	}
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(dir), &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Findings) != 1 || findings.Findings[0].Status != "likely_issue" || findings.Findings[0].VerificationBasis != "source_corroborated_no_query" {
		t.Fatalf("findings: %+v", findings)
	}
	var memo artifacts.VerificationMemo
	if err := runfs.ReadJSON(filepath.Join(runfs.VerifierDir(dir), "verify-001.json"), &memo); err != nil {
		t.Fatal(err)
	}
	if len(memo.InvariantAssessments) != 1 || memo.InvariantAssessments[0].Assessment != "unresolved" || len(memo.InvariantUpdates) != 0 {
		t.Fatalf("memo: %+v", memo)
	}
	if report := runvalidate.Validate(dir); !report.Valid {
		t.Fatalf("invalid bundle: %+v", report.Issues)
	}
}
