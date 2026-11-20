package expert

import (
	"context"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contractreview"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func buildContractHypothesis(ctx context.Context, client llm.Client, manifest artifacts.Manifest, cfg config.Config, pack artifacts.CasePack) (artifacts.Hypothesis, error) {
	h := artifacts.Hypothesis{SchemaVersion: "teecheck.hypothesis.v1", CaseID: pack.CaseID, AgentID: cfg.AgentID,
		Title: "Source review of case contracts", Confidence: "low", NeedsVerification: true}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: manifest.LocalPath, Scope: manifest.Scope}
	var reasons []string
	for _, c := range pack.CaseInvariants {
		r, err := contractreview.Review(ctx, client, "expert", binding, c, nil, cfg.LLMTemp)
		if err != nil {
			return h, err
		}
		h.ContractReviews = append(h.ContractReviews, r)
		reasons = append(reasons, c.InvariantID+": "+r.Reason)
	}
	h.Summary = strings.Join(reasons, "\n")
	h.SuspectedIssue = "See individual contract reviews; each requires independent verification."
	return h, nil
}
