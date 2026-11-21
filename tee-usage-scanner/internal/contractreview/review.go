// Package contractreview performs source-grounded, per-contract reviews. A
// review is an agent opinion; only the verifier may turn tool execution into
// an InvariantAssessment.
package contractreview

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// Review never accepts a model-supplied assessment or tool result. Peer reviews
// are supplied only to the verifier; the independent reviewers receive none.
func Review(ctx context.Context, client llm.Client, role string, binding contracts.BindingContext, c artifacts.CaseInvariantV2, peers []artifacts.ContractReview, temperature float64, facts ...artifacts.ToolFact) (artifacts.ContractReview, error) {
	if c.Grounding != "source_bound" {
		return unresolved(c.InvariantID, "contract has no validated source binding"), nil
	}
	if err := contracts.Validate(c, binding); err != nil {
		return unresolved(c.InvariantID, "contract binding failed: "+err.Error()), nil
	}
	// Contracts reference the immutable trace artifact; never rely on a model
	// copying a path summary into its own conclusions. The same source facts
	// are available independently to Expert, Challenger and Verifier.
	seenFacts := map[string]bool{}
	for _, fact := range facts {
		seenFacts[fact.FactID] = true
	}
	for _, ref := range c.EvidenceRefs {
		if ref.Kind != "tool_fact" {
			continue
		}
		fact, err := contracts.LoadToolFact(ref.Ref, binding)
		if err != nil {
			return unresolved(c.InvariantID, "contract tool evidence failed: "+err.Error()), nil
		}
		if !seenFacts[fact.FactID] {
			facts = append(facts, fact)
			seenFacts[fact.FactID] = true
		}
	}
	if client == nil {
		return unresolved(c.InvariantID, "review client unavailable"), nil
	}
	source, err := sourceContext(binding.RepoRoot, c)
	if err != nil {
		return unresolved(c.InvariantID, err.Error()), nil
	}
	definition, _ := json.Marshal(c)
	peerJSON, _ := json.Marshal(peers)
	system := `You review a defensive source-code contract for TEECheck. Evaluate only the supplied contract and code, without inventing tool executions or drawing conclusions about other contracts.
Return one JSON object with fields: invariant_id, position (supported|contradicted|unresolved), reason, preconditions_satisfied (boolean), attack_chain_complete (boolean), witness (array of {path,symbol,start_line,end_line}), counter_evidence (array of strings).
"supported" means the source supports a security-relevant violation of the required property under its preconditions, not that the code satisfies the property. Explain how it affects the stated security decision. A syntactic difference alone does not establish a security issue. "contradicted" means the proposed violation has contrary evidence. These are source-review opinions, not deterministic proof.
Set preconditions_satisfied only when every necessary precondition has source support. Set attack_chain_complete only when the relevant input, property violation and security effect are connected by evidence; do not infer completeness from missing objections. Identify each unresolved relation explicitly. A witness must cite actual lines within this contract's supplied source anchors. Do not use a conclusion about another contract as evidence.`
	system += "\nThe query parameters identify the local property target; the other subjects provide consumer/caller context for preconditions and effects. Judge the property separately from missing runtime context. A successful registered local query is not invalidated merely because cross-function preconditions are unproved; record those gaps honestly."
	user := fmt.Sprintf("Role: %s\nContract:\n%s\nSource anchors:\n%s", role, definition, source)
	factsOmitted := false
	if len(peers) > 0 {
		user += "\nIndependent per-contract review opinions (check against the code):\n" + string(peerJSON)
	}
	if len(facts) > 0 {
		var evidence strings.Builder
		omitted := 0
		for _, fact := range facts {
			var rendered string
			if fact.Operation == artifacts.TaintTraceOperation {
				rendered = artifacts.FormatToolFact(fact)
			} else {
				data, _ := json.Marshal(fact)
				rendered = string(data)
			}
			if evidence.Len()+len(rendered) > 32*1024 {
				omitted++
				continue
			}
			evidence.WriteString(rendered)
			evidence.WriteByte('\n')
		}
		if omitted > 0 {
			factsOmitted = true
			fmt.Fprintf(&evidence, "%d additional immutable fact(s) omitted from this prompt; references remain in the contract. Do not infer their contents.\n", omitted)
		}
		user += "\nExecutor observations (immutable; not verdicts; do not claim other tools ran):\n" + evidence.String()
		user += "\nTaint paths describe possible flow in the configured static model. No paths or configured barrier filters do not establish safety. Confirm the actual guards and data relationships in source."
	}
	var review artifacts.ContractReview
	_, err = llm.GenerateJSON(ctx, client, role, llm.GenerateRequest{
		SystemPrompt: system, Messages: []llm.Message{{Role: "user", Content: user}},
		Temperature: temperature, JSONMode: true,
	}, &review)
	if err != nil {
		return artifacts.ContractReview{}, err
	}
	if factsOmitted {
		review.Position = "unresolved"
		review.AttackChainComplete = false
		review.Reason += " Some referenced tool evidence exceeded the review prompt budget."
	}
	return ValidateReview(review, c, binding), nil
}

// ValidateReview checks ownership and fresh source anchors before an opinion
// may contribute to a source-corroborated finding.
func ValidateReview(r artifacts.ContractReview, c artifacts.CaseInvariantV2, binding contracts.BindingContext) artifacts.ContractReview {
	if r.InvariantID != c.InvariantID {
		return unresolved(c.InvariantID, "review names a different contract")
	}
	switch r.Position {
	case "supported", "contradicted", "unresolved":
	default:
		return unresolved(c.InvariantID, "invalid review position")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return unresolved(c.InvariantID, "review has no explanation")
	}
	for i, witness := range r.Witness {
		if !withinContract(witness, c) {
			return unresolved(c.InvariantID, "witness is outside this contract's source anchors")
		}
		bound, err := contracts.BindSubject(witness, binding)
		if err != nil {
			return unresolved(c.InvariantID, "witness binding failed: "+err.Error())
		}
		r.Witness[i] = bound
	}
	if r.Position != "unresolved" && len(r.Witness) == 0 {
		return unresolved(c.InvariantID, "source review has no anchored witness")
	}
	if len(r.CounterEvidence) > 0 && r.Position == "supported" {
		r.Position = "unresolved"
		r.AttackChainComplete = false
	}
	return r
}

func withinContract(w artifacts.ContractSubject, c artifacts.CaseInvariantV2) bool {
	for _, s := range c.Subjects {
		if filepath.ToSlash(w.Path) == filepath.ToSlash(s.Path) && w.Symbol == s.Symbol &&
			w.StartLine >= s.StartLine && w.EndLine >= w.StartLine && w.EndLine <= s.EndLine {
			return true
		}
	}
	return false
}

func unresolved(id, reason string) artifacts.ContractReview {
	return artifacts.ContractReview{InvariantID: id, Position: "unresolved", Reason: reason}
}

func sourceContext(root string, c artifacts.CaseInvariantV2) (string, error) {
	var out strings.Builder
	for _, s := range c.Subjects {
		if _, err := contracts.BindSubject(s, contracts.BindingContext{RepoRoot: root, Scope: c.Scope}); err != nil {
			return "", fmt.Errorf("invalid source anchor: %w", err)
		}
		data, err := os.ReadFile(filepath.Join(root, s.Path))
		if err != nil {
			return "", fmt.Errorf("read source anchor: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		if s.StartLine < 1 || s.EndLine < s.StartLine || s.EndLine > len(lines) {
			return "", fmt.Errorf("invalid source range for %s", s.Path)
		}
		fmt.Fprintf(&out, "\n%s :: %s\n", s.Path, s.Symbol)
		for n := s.StartLine; n <= s.EndLine; n++ {
			fmt.Fprintf(&out, "%d: %s\n", n, lines[n-1])
		}
		if out.Len() > 48*1024 {
			return "", fmt.Errorf("contract source exceeds review byte budget")
		}
	}
	return out.String(), nil
}

// Find returns only an unambiguous opinion for this contract. Duplicate model
// entries must not make the last answer silently win.
func Find(reviews []artifacts.ContractReview, id string) (artifacts.ContractReview, bool) {
	var found artifacts.ContractReview
	count := 0
	for _, r := range reviews {
		if r.InvariantID == id {
			found, count = r, count+1
		}
	}
	return found, count == 1
}
