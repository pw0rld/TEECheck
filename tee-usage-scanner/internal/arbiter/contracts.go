package arbiter

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contractreview"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
)

func arbitrateContracts(runDir string, manifest artifacts.Manifest, pack artifacts.CasePack, h artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo) ([]artifacts.FindingItem, []string) {
	binding := contracts.BindingContext{RunDir: runDir, RepoRoot: manifest.LocalPath, Scope: manifest.Scope}
	var items []artifacts.FindingItem
	var packets []string
	if len(pack.CaseInvariants) == 0 {
		item := artifacts.FindingItem{FindingID: pack.CaseID, SliceID: pack.CaseID, Status: "needs_review", Severity: severityForCategory(pack.Category), Confidence: "low", Files: pack.TargetFiles,
			Summary: "The investigation has not produced a bound case contract.", VerificationBasis: "contract_unformalized", RelatedTWEs: pack.RelatedTWEs}
		return []artifacts.FindingItem{item}, []string{"# Contract review\n\n" + item.Summary + "\n"}
	}
	for _, c := range pack.CaseInvariants {
		item := artifacts.FindingItem{FindingID: pack.CaseID + ":" + c.InvariantID, SliceID: pack.CaseID, InvariantID: c.InvariantID,
			Origin:                  c.Origin,
			InvariantDefinitionHash: c.DefinitionHash, Status: "needs_review", Severity: severityForCategory(pack.Category), Confidence: "low",
			Summary: c.RequiredProperty.Statement, VerificationBasis: "assessment_unavailable", RelatedTWEs: c.RelatedTWEs}
		a, ok := uniqueAssessment(memo.InvariantAssessments, c.InvariantID)
		if err := contracts.Validate(c, binding); err != nil {
			item.Evidence = append(item.Evidence, "Contract validation failed: "+err.Error())
		} else if !ok {
			item.Evidence = append(item.Evidence, "A unique assessment for this contract is missing.")
		} else if err := contracts.ValidateAssessment(a, c, binding); err != nil {
			item.Evidence = append(item.Evidence, "Assessment validation failed: "+err.Error())
		} else {
			item.VerificationBasis = a.VerificationBasis
			item.Evidence = append(item.Evidence, a.Reason)
			switch a.Assessment {
			case "satisfied":
				if len(a.Contradictions) == 0 {
					item.Status, item.Confidence = "no_issue_observed", "high"
				}
			case "violated":
				if consistentReviews(c, a, h.ContractReviews, challenge.ContractReviews, binding) {
					item.Status, item.Confidence = "likely_issue", "medium"
					if contractChainComplete(c, a, h.ContractReviews, challenge.ContractReviews, binding) {
						item.Status, item.Confidence = "confirmed_candidate", "high"
					}
				}
			case "unresolved":
				if sourceOnlyLikely(c, a, h.ContractReviews, challenge.ContractReviews, binding) {
					item.Status, item.Confidence = "likely_issue", "medium"
				}
			}
			for _, w := range a.Witness {
				item.Locations = append(item.Locations, artifacts.FindingLocation{Path: w.Path, StartLine: w.StartLine, Symbol: w.Symbol})
			}
			item.Evidence = append(item.Evidence, a.Contradictions...)
		}
		for _, s := range c.Subjects {
			item.Files = appendUniqueString(item.Files, s.Path)
		}
		if item.Summary == "" {
			item.Summary = "Contract requires further review."
		}
		item.Sections = &artifacts.ArbiterSections{InvariantVerificationStatus: []string{fmt.Sprintf("%s: %s (%s)", c.InvariantID, a.Assessment, a.ReasonCode)},
			RemainingCoverageGaps: append([]string{}, a.MissingEvidence...), VerifierResolution: a.Reason}
		items = append(items, item)
		packets = append(packets, fmt.Sprintf("# Contract review: %s\n\n- Status: `%s`\n- Contract digest: `%s`\n- Verification basis: `%s`\n\n%s\n\n%s\n", c.InvariantID, item.Status, c.DefinitionHash, item.VerificationBasis, item.Summary, strings.Join(item.Evidence, "\n")))
	}
	return items, packets
}

func uniqueAssessment(all []artifacts.InvariantAssessment, id string) (artifacts.InvariantAssessment, bool) {
	var result artifacts.InvariantAssessment
	n := 0
	for _, a := range all {
		if a.InvariantID == id {
			result, n = a, n+1
		}
	}
	return result, n == 1
}

func consistentReviews(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	return contractreview.ConsistentReviews(c, a, experts, challengers, binding)
}

func contractChainComplete(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	return contractreview.ChainComplete(c, a, experts, challengers, binding)
}

func sourceOnlyLikely(c artifacts.CaseInvariantV2, a artifacts.InvariantAssessment, experts, challengers []artifacts.ContractReview, binding contracts.BindingContext) bool {
	return contractreview.SourceOnlyLikely(c, a, experts, challengers, binding)
}

func appendUniqueString(all []string, s string) []string {
	for _, old := range all {
		if s == old {
			return all
		}
	}
	return append(all, s)
}
