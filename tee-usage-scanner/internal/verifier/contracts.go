package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contractreview"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func buildContractMemo(ctx context.Context, cfg config.Config, client llm.Client, manifest artifacts.Manifest, pack artifacts.CasePack, h artifacts.Hypothesis, challenge artifacts.Challenge, runner ContractQueryRunner) (artifacts.VerificationMemo, error) {
	memo := artifacts.VerificationMemo{SchemaVersion: "teecheck.verification_memo.v1", CaseID: pack.CaseID, AgentID: cfg.AgentID, Status: "inconclusive"}
	binding := contracts.BindingContext{RunDir: cfg.RunDir, RepoRoot: manifest.LocalPath, Scope: manifest.Scope}
	queriesUsed := 0
	for _, c := range pack.CaseInvariants {
		if err := contracts.Validate(c, binding); err != nil {
			return memo, fmt.Errorf("invalid persisted contract %s: %w", c.InvariantID, err)
		}
		query := ContractQueryResult{Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "No registered query applies to this property."}
		if c.RequiredProperty.Kind == "direct_struct_field_assignment" {
			query.ReasonCode, query.Reason = "query_not_configured", "This property has a registered query, but the contract did not configure it."
		}
		operation := ""
		var facts []artifacts.ToolFact
		for _, q := range c.VerificationQueries {
			if !registeredQuery(c, q) {
				continue
			}
			operation = q.Operation
			if queriesUsed >= maxVerifierQueries {
				query = ContractQueryResult{Assessment: "unresolved", ReasonCode: "query_budget", Reason: "Contract query budget exhausted."}
				break
			}
			queriesUsed++
			if runner == nil {
				query = ContractQueryResult{Assessment: "unresolved", ReasonCode: "tool_unavailable", Reason: "No registered query executor was supplied."}
			} else {
				var err error
				query, err = runner.Run(ctx, c, q)
				if err != nil {
					return memo, err
				}
				if query.FactRef != "" {
					facts = append(facts, query.Fact)
				}
			}
			// The first registered query owns this property's result. A later
			// unsupported query must not erase its error or contradict it.
			break
		}
		var peers []artifacts.ContractReview
		if r, ok := contractreview.Find(h.ContractReviews, c.InvariantID); ok {
			peers = append(peers, r)
		}
		if r, ok := contractreview.Find(challenge.ContractReviews, c.InvariantID); ok {
			peers = append(peers, r)
		}
		v, err := contractreview.Review(ctx, client, "verifier", binding, c, peers, cfg.LLMTemp, facts...)
		if err != nil {
			return memo, err
		}
		a := AssessContract(c, binding, h.ContractReviews, challenge.ContractReviews, v, query)
		a.QueryOperation = operation
		if err := contracts.ValidateAssessment(a, c, binding); err != nil {
			return memo, fmt.Errorf("invalid assessment %s: %w", c.InvariantID, err)
		}
		if err := persistContractAssessment(cfg.RunDir, a); err != nil {
			return memo, err
		}
		memo.InvariantAssessments = append(memo.InvariantAssessments, a)
	}
	// Deliberately no InvariantUpdates: a case-level memo cannot update the
	// truth value of each independently assessed obligation.
	return memo, nil
}

// AssessContract keeps a registered query's local result separate from the
// evidence needed to turn that result into a security finding. Missing runtime
// preconditions cannot erase a verified syntactic result, or establish impact.
func AssessContract(c artifacts.CaseInvariantV2, binding contracts.BindingContext, experts, challengers []artifacts.ContractReview, review artifacts.ContractReview, query ContractQueryResult) artifacts.InvariantAssessment {
	a := artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID,
		DefinitionHash: c.DefinitionHash, Scope: c.Scope, Assessment: "unresolved", ReasonCode: query.ReasonCode,
		Reason: query.Reason, VerificationBasis: "unresolved", EvidenceRefs: append([]artifacts.ContractEvidenceRef{}, c.EvidenceRefs...), Witness: []artifacts.ContractSubject{}}
	v := contractreview.ValidateReview(review, c, binding)
	a.Witness, a.PreconditionsSatisfied = v.Witness, v.PreconditionsSatisfied
	e, eok := contractreview.Find(experts, c.InvariantID)
	ch, chok := contractreview.Find(challengers, c.InvariantID)
	if eok {
		e = contractreview.ValidateReview(e, c, binding)
	}
	if chok {
		ch = contractreview.ValidateReview(ch, c, binding)
	}
	reviews := []artifacts.ContractReview{v}
	if eok {
		reviews = append(reviews, e)
	}
	if chok {
		reviews = append(reviews, ch)
	}
	for _, r := range reviews {
		if query.Assessment == "satisfied" {
			// A source review against the proposed violation agrees with a
			// satisfied query; only a claimed violation conflicts with it.
			if r.Position == "contradicted" {
				if len(r.CounterEvidence) > 0 {
					a.Reason += " Source evidence against the proposed violation: " + strings.Join(r.CounterEvidence, "; ")
				}
			} else {
				a.Contradictions = append(a.Contradictions, r.CounterEvidence...)
			}
			if r.Position == "supported" {
				a.Contradictions = append(a.Contradictions, r.Reason)
			}
		} else {
			a.Contradictions = append(a.Contradictions, r.CounterEvidence...)
			if r.Position == "contradicted" {
				a.Contradictions = append(a.Contradictions, r.Reason)
			}
		}
	}
	a.SourceCorroborated = eok && chok && e.Position == "supported" && ch.Position == "supported" && v.Position == "supported" && len(v.Witness) > 0
	a.AttackChainComplete = a.SourceCorroborated && a.PreconditionsSatisfied && e.AttackChainComplete && ch.AttackChainComplete && v.AttackChainComplete
	if query.FactRef != "" {
		ref, err := contracts.ResolveEvidence(artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: query.FactRef}, binding)
		if err != nil {
			a.ReasonCode, a.Reason = "invalid_tool_evidence", err.Error()
			return a
		}
		a.EvidenceRefs = append(a.EvidenceRefs, ref)
	}
	if (query.Assessment == "violated" || query.Assessment == "satisfied") && query.Fact.Status == "success" && query.FactRef != "" {
		candidate := a
		candidate.Assessment, candidate.VerificationBasis = query.Assessment, "registered_query"
		candidate.QueryOperation = query.Fact.Operation
		// These are validated current-revision subject anchors, not model
		// assertions. They support the registered query's narrowly scoped result.
		candidate.Witness = append([]artifacts.ContractSubject{}, c.Subjects...)
		candidate.SourceCorroborated = len(v.Witness) > 0 && ((query.Assessment == "violated" && v.Position == "supported") || (query.Assessment == "satisfied" && v.Position == "contradicted"))
		if !candidate.PreconditionsSatisfied {
			candidate.MissingEvidence = append(candidate.MissingEvidence, "precondition_unproven: "+strings.Join(c.Preconditions, "; "))
		}
		if !candidate.SourceCorroborated {
			candidate.MissingEvidence = append(candidate.MissingEvidence, "source_review_unresolved: "+v.Reason)
		}
		if len(candidate.Contradictions) > 0 {
			candidate.MissingEvidence = append(candidate.MissingEvidence, "Resolve the source review's disagreement with the registered query.")
		}
		if len(candidate.MissingEvidence) > 0 || len(candidate.Contradictions) > 0 {
			candidate.AttackChainComplete = false
		}
		if err := contracts.ValidateAssessment(candidate, c, binding); err != nil {
			a.ReasonCode, a.Reason = "invalid_tool_evidence", err.Error()
			a.AttackChainComplete = false
			return a
		}
		return candidate
	}
	a.AttackChainComplete = a.AttackChainComplete && len(a.Contradictions) == 0
	if query.ReasonCode == "no_registered_query" && c.RequiredProperty.Kind != "direct_struct_field_assignment" {
		if v.Position == "contradicted" && len(v.Witness) > 0 {
			a.ReasonCode, a.Reason = "source_contradicted", v.Reason
			return a
		}
		if !v.PreconditionsSatisfied {
			a.ReasonCode, a.Reason = "precondition_unproven", "Verifier could not establish all contract preconditions."
			return a
		}
		if len(a.Contradictions) > 0 {
			a.ReasonCode, a.Reason = "counterevidence", "This contract has unresolved counter-evidence."
			return a
		}
		if a.SourceCorroborated {
			a.VerificationBasis = "source_corroborated_no_query"
		}
	}
	return a
}

func persistContractAssessment(runDir string, a artifacts.InvariantAssessment) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	path := filepath.Join(runfs.VerifierDir(runDir), "assessments", hex.EncodeToString(sum[:])+".json")
	return runfs.WriteJSON(path, a)
}

// Reverify evaluates a freshly rebound logical contract. It never runs the
// planner, reads old findings, or supplies earlier witnesses to the reviewer.
func Reverify(ctx context.Context, cfg config.Config, c artifacts.CaseInvariantV2, binding contracts.BindingContext, runner ContractQueryRunner) (artifacts.InvariantAssessment, error) {
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		return artifacts.InvariantAssessment{}, err
	}
	role := roles["verifier"]
	cfg = cfg.WithLLMSettingsFrom(role)
	var client llm.Client
	if cfg.LLMModel != "" && cfg.LLMBaseURL != "" && cfg.LLMAPIKey != "" {
		client = llm.NewClient(cfg)
	}
	return ReverifyWithClient(ctx, cfg, client, c, binding, runner)
}

func ReverifyWithClient(ctx context.Context, cfg config.Config, client llm.Client, c artifacts.CaseInvariantV2, binding contracts.BindingContext, runner ContractQueryRunner) (artifacts.InvariantAssessment, error) {
	cfg.RunDir = binding.RunDir
	manifest := artifacts.Manifest{RunID: cfg.RunID, RepoURL: binding.Scope.RepoURL, Commit: binding.Scope.Commit, LocalPath: binding.RepoRoot, Scope: binding.Scope}
	pack := artifacts.CasePack{CaseID: "reverify:" + c.InvariantID, ContractRequired: true, CaseInvariants: []artifacts.CaseInvariantV2{c}}
	memo, err := buildContractMemo(ctx, cfg, client, manifest, pack, artifacts.Hypothesis{}, artifacts.Challenge{}, runner)
	if err != nil {
		return artifacts.InvariantAssessment{}, err
	}
	if len(memo.InvariantAssessments) != 1 {
		return artifacts.InvariantAssessment{}, fmt.Errorf("expected exactly one contract assessment")
	}
	return memo.InvariantAssessments[0], nil
}
