package pipeline_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runvalidate"
)

type sourceLeadClient struct{ calls int }

func (c *sourceLeadClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	switch c.calls {
	case 1:
		return llm.GenerateResponse{Text: `{"actions":[{"name":"get_repository_card","args":{}},{"name":"list_dir","args":{"path":".","depth":1}},{"name":"read_file","args":{"path":"demo.c","start":1,"end":4}}]}`}, nil
	case 2:
		match := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
		if len(match) != 2 {
			return llm.GenerateResponse{}, fmt.Errorf("successful source observation was not exposed")
		}
		payload := map[string]any{"actions": []any{map[string]any{
			"name": "open_audit_lead", "args": map[string]any{
				"security_question": "Does verify reject non-positive input?",
				"target_symbol_ids": []string{"demo.c::verify"},
				"reason":            []string{"The observed function makes the decision."},
				"reason_fact_refs":  []string{match[1]},
			},
		}}}
		body, _ := json.Marshal(payload)
		return llm.GenerateResponse{Text: string(body)}, nil
	case 3:
		if !strings.Contains(req.SystemPrompt, "Investigator") {
			return llm.GenerateResponse{}, fmt.Errorf("source lead did not enter investigation")
		}
		return llm.GenerateResponse{Text: plannerDoneJSON}, nil
	default:
		return llm.GenerateResponse{}, fmt.Errorf("unexpected additional model call %d", c.calls)
	}
}

func TestPipeline_SourceOnlyLeadReachesDoneWithValidBundle(t *testing.T) {
	source := t.TempDir() // Outside the checkout, so source scope cannot widen.
	if err := os.WriteFile(filepath.Join(source, "demo.c"), []byte("int verify(int value) { return value > 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	client := &sourceLeadClient{}
	dir, err := pipeline.RunWithClient(config.Config{
		Command: "run", Target: source, Mode: "llm", Focus: "tee", RunID: "source-only-smoke",
		OutputDir: out, KnowledgeRoot: filepath.Join(out, "knowledge"),
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	var bundle artifacts.EvidenceBundle
	if err := runfs.ReadJSON(runfs.EvidenceBundlePath(dir), &bundle); err != nil {
		t.Fatal(err)
	}
	if client.calls != 3 || bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Fatalf("calls=%d termination=%s", client.calls, bundle.PlannerMeta.TerminationReason)
	}
	if result := runvalidate.Validate(dir); !result.Valid {
		t.Fatalf("invalid run bundle: %+v", result.Issues)
	}
}
