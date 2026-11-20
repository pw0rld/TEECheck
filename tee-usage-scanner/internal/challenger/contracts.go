package challenger

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contractreview"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// No hypothesis is accepted by this function. Its output is persisted before
// phase two reads the expert, preserving the independent-review boundary.
func buildContractIndependent(ctx context.Context, client llm.Client, manifest artifacts.Manifest, cfg config.Config, pack artifacts.CasePack) (artifacts.ChallengerIndependentView, error) {
	v := artifacts.ChallengerIndependentView{SchemaVersion: "teecheck.challenger_independent.v1", CaseID: pack.CaseID, AgentID: cfg.AgentID, Confidence: "low"}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: manifest.LocalPath, Scope: manifest.Scope}
	var reasons []string
	for _, c := range pack.CaseInvariants {
		r, err := contractreview.Review(ctx, client, "challenger", binding, c, nil, cfg.LLMTemp)
		if err != nil {
			return v, err
		}
		v.ContractReviews = append(v.ContractReviews, r)
		v.IssuePresent = v.IssuePresent || r.Position == "supported"
		v.CounterExamples = append(v.CounterExamples, r.CounterEvidence...)
		reasons = append(reasons, c.InvariantID+": "+r.Reason)
	}
	v.Reasoning = strings.Join(reasons, "\n")
	return v, nil
}

// Comparison is deterministic: seeing the expert cannot replace the already
// persisted independent opinion with an agreeable second model response.
func compareContractReviews(pack artifacts.CasePack, h artifacts.Hypothesis, v artifacts.ChallengerIndependentView, agentID string) artifacts.Challenge {
	c := artifacts.Challenge{SchemaVersion: "teecheck.challenge.v1", CaseID: pack.CaseID, AgentID: agentID,
		IndependentIssuePresent: v.IssuePresent, Exploitability: "unrated", ReviewerStance: "contract_review",
		ExploitNarrative: v.Reasoning, ContractReviews: v.ContractReviews}
	for _, inv := range pack.CaseInvariants {
		e, eok := contractreview.Find(h.ContractReviews, inv.InvariantID)
		i, iok := contractreview.Find(v.ContractReviews, inv.InvariantID)
		if !eok || !iok || e.Position != i.Position {
			c.KeyDifferences = append(c.KeyDifferences, fmt.Sprintf("%s: expert=%s independent=%s", inv.InvariantID, e.Position, i.Position))
		}
		c.CounterArguments = append(c.CounterArguments, i.CounterEvidence...)
	}
	return c
}
