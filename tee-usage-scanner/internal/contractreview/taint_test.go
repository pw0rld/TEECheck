package contractreview

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

type taintReviewClient struct {
	request   llm.GenerateRequest
	invariant string
}

func (c *taintReviewClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.request = req
	body, _ := json.Marshal(artifacts.ContractReview{InvariantID: c.invariant, Position: "unresolved", Reason: "Source relationship needs review"})
	return llm.GenerateResponse{Text: string(body)}, nil
}

func TestReviewLoadsImmutableTaintEvidenceForEveryIndependentRole(t *testing.T) {
	for _, role := range []string{"expert", "challenger", "verifier"} {
		t.Run(role, func(t *testing.T) {
			root, run := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "entry.c"), []byte("int entry(int value) { return value; }\n"), 0600); err != nil {
				t.Fatal(err)
			}
			scope := runfs.BuildScope("fixture", "rev", root)
			fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, RequestID: "trace", FactID: "taint-fixture", Tool: "codeql-cpp-taint", Operation: artifacts.TaintTraceOperation, RepoCommit: "rev", Scope: &scope, Status: "success", Result: json.RawMessage(`{"total_paths":0,"barriers_applied":["check"]}`)}
			fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			path, err := trustirfacts.Persist(run, fact)
			if err != nil {
				t.Fatal(err)
			}
			ctx := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: scope}
			contract, _, err := contracts.Bind(artifacts.CaseInvariantV2{Origin: "planner", LeadRef: "lead", Subjects: []artifacts.ContractSubject{{Path: "entry.c", Symbol: "entry"}}, Preconditions: []string{"input can be external"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "validate before accepting"}, SecurityEffect: "acceptance", EvidenceRefs: []artifacts.ContractEvidenceRef{{Kind: "tool_fact", Ref: path}}}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			client := &taintReviewClient{invariant: contract.InvariantID}
			review, err := Review(context.Background(), client, role, ctx, contract, nil, 0)
			if err != nil || review.Position != "unresolved" {
				t.Fatalf("review=%+v error=%v", review, err)
			}
			prompt := client.request.Messages[0].Content
			for _, wanted := range []string{fact.FactID, "Zero paths", "do NOT prove safety", "Syntactic call-result filters"} {
				if !strings.Contains(prompt, wanted) {
					t.Errorf("missing %q", wanted)
				}
			}
		})
	}
}
