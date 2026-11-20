package contractreview

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type neverClient struct{ calls int }

func (c *neverClient) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	return llm.GenerateResponse{}, nil
}

func TestReview_UnboundContractCannotReadOutsideRepository(t *testing.T) {
	c := artifacts.CaseInvariantV2{InvariantID: "inv", Origin: "planner", Grounding: "unresolved", Subjects: []artifacts.ContractSubject{{Path: "../outside.c", Symbol: "secret", StartLine: 1, EndLine: 1}}, Preconditions: []string{"input"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "check input"}, SecurityEffect: "decision"}
	c.DefinitionHash = contracts.DefinitionHash(c)
	client := &neverClient{}
	r, err := Review(context.Background(), client, "verifier", contracts.BindingContext{RepoRoot: t.TempDir()}, c, nil, 0)
	if err != nil || client.calls != 0 || r.Position != "unresolved" {
		t.Fatalf("unbound contract reached model: %+v %v calls=%d", r, err, client.calls)
	}
}
