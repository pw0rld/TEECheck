// Package judge defines the evaluator-side contract for semantic overlap
// judgments. Implementations may call an LLM, but never run inside TEECheck.
package judge

import (
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/teecheck-benchmark/evaluator/rag"
)

type Decision struct {
	CaseID          string   `json:"case_id"`
	Variant         string   `json:"variant"`
	Overlap         bool     `json:"overlap"`
	Confidence      float64  `json:"confidence"`
	RootCauseMatch  bool     `json:"root_cause_match"`
	LocationMatch   bool     `json:"location_match"`
	ImpactMatch     bool     `json:"impact_match"`
	MatchedEvidence []string `json:"matched_evidence"`
	Reason          string   `json:"reason"`
	Classification  string   `json:"classification"`
}

type Judge interface {
	Judge(report rag.Report, hit rag.Hit) (Decision, error)
}

func Prompt(report rag.Report, hit rag.Hit) (string, error) {
	payload := struct {
		ScannerReport rag.Report `json:"scanner_report"`
		Candidate     rag.Case   `json:"candidate_case"`
	}{report, hit.Case}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Determine whether the scanner report describes the same vulnerability as the candidate benchmark case. Require root cause, code location, and security impact alignment. Do not treat a shared file name alone as a match. Return the structured decision schema.\n\n%s", b), nil
}
