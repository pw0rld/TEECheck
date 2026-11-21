package contractreview

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
)

// ConsistentReviews is the shared evidence gate used by arbitration and
// offline validation. It reads source anchors but never changes the supplied
// artifacts or derives a new assessment from the review opinions.
func ConsistentReviews(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	if c.Grounding != "source_bound" || a.InvariantID != c.InvariantID || a.DefinitionHash != c.DefinitionHash || !a.SourceCorroborated || !a.PreconditionsSatisfied || len(a.Witness) == 0 || len(a.Contradictions) > 0 || len(a.MissingEvidence) > 0 {
		return false
	}
	for _, all := range [][]artifacts.ContractReview{experts, challengers} {
		r, ok := Find(all, c.InvariantID)
		if !ok {
			return false
		}
		// ValidateReview binds each witness afresh. Copy its slice so this
		// predicate cannot replace anchors inside a caller's persisted review.
		r.Witness = append([]artifacts.ContractSubject(nil), r.Witness...)
		r = ValidateReview(r, c, binding)
		if r.Position != "supported" || !r.PreconditionsSatisfied || len(r.Witness) == 0 || len(r.CounterEvidence) > 0 {
			return false
		}
	}
	return true
}

// ChainComplete requires both independent per-contract reviews to establish
// the chain, not merely a case-wide summary or an assessment's boolean flag.
func ChainComplete(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	if a.Assessment != "violated" || !a.AttackChainComplete || !ConsistentReviews(c, a, experts, challengers, binding) {
		return false
	}
	for _, all := range [][]artifacts.ContractReview{experts, challengers} {
		r, _ := Find(all, c.InvariantID)
		if !r.AttackChainComplete {
			return false
		}
	}
	return true
}

// SourceOnlyLikely is intentionally narrower than an unresolved assessment:
// registered-query failures and missing query configuration cannot use it.
func SourceOnlyLikely(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	return c.RequiredProperty.Kind != "direct_struct_field_assignment" && a.Assessment == "unresolved" && a.ReasonCode == "no_registered_query" && a.VerificationBasis == "source_corroborated_no_query" && ConsistentReviews(c, a, experts, challengers, binding)
}
