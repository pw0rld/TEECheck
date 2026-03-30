package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/evidence"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/report"
)

type Rule struct {
	ID                 string          `json:"rule_id"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Scope              string          `json:"scope"`
	TriggerKinds       []string        `json:"trigger_kinds"`
	TargetSymbols      []string        `json:"target_symbols,omitempty"`
	RequiredChecks     []RequiredCheck `json:"required_checks"`
	RecommendedChecks  []AdvisoryCheck `json:"recommended_checks,omitempty"`
	EvidenceNeeds      []string        `json:"evidence_requirements,omitempty"`
	Confidence         ConfidenceHints `json:"confidence_strategy,omitempty"`
	LLMReviewQuestions []string        `json:"llm_review_questions,omitempty"`
	Severity           string          `json:"severity"`
	LLMReviewRequired  bool            `json:"llm_review_required"`
}

type RequiredCheck struct {
	Kind             string   `json:"kind"`
	MustDominate     bool     `json:"must_dominate"`
	EvidenceExamples []string `json:"evidence_examples,omitempty"`
	RequiredFields   []string `json:"required_fields,omitempty"`
}

type AdvisoryCheck struct {
	Kind string `json:"kind"`
	Why  string `json:"why,omitempty"`
}

type ConfidenceHints struct {
	High        string `json:"high,omitempty"`
	Medium      string `json:"medium,omitempty"`
	NeedsReview string `json:"needs_review,omitempty"`
}

func LoadDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		rule, err := parseRule(data)
		if err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", path, err)
		}
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return rules, nil
}

func parseRule(data []byte) (Rule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var rule Rule
	if err := dec.Decode(&rule); err != nil {
		return Rule{}, err
	}
	if rule.ID == "" {
		return Rule{}, fmt.Errorf("missing rule_id")
	}
	return rule, nil
}

func Evaluate(rule Rule, ev evidence.Package) (report.Finding, bool) {
	if !slices.Contains(rule.TriggerKinds, ev.Candidate.OperationKind) {
		return report.Finding{}, false
	}

	missing := []string{}
	observed := []string{}

	for _, req := range rule.RequiredChecks {
		status := evaluateRequiredCheck(req, ev.Checks)
		for _, item := range status.observed {
			observed = appendObserved(observed, item)
		}
		if status.satisfied {
			continue
		}

		missing = append(missing, requirementLabel(req.Kind, status.missingFields))
		if status.presentButNotDominating {
			observed = appendObserved(observed, req.Kind+":present_but_not_dominating")
		}
	}

	if len(missing) == 0 {
		return report.Finding{}, false
	}

	needsReview := rule.LLMReviewRequired && ev.Metadata["review_recommended"] == "true"
	status := "finding"
	if needsReview {
		status = "needs_review"
	}

	scope := ev.Candidate.Function
	if scope == "" {
		scope = ev.Candidate.Expression
	}
	if scope == "" {
		scope = ev.Candidate.ID
	}
	message := fmt.Sprintf("%s candidate in %s is missing required checks: %s.", humanizeKind(ev.Candidate.OperationKind), scope, strings.Join(missing, ", "))
	return report.Finding{
		ID:             ev.Candidate.ID + "::" + rule.ID,
		RuleID:         rule.ID,
		Severity:       rule.Severity,
		Status:         status,
		File:           ev.Candidate.File,
		Line:           ev.Candidate.Line,
		Function:       ev.Candidate.Function,
		Expression:     ev.Candidate.Expression,
		Message:        message,
		MissingChecks:  missing,
		ObservedChecks: observed,
		NeedsReview:    needsReview,
	}, true
}

type checkStatus struct {
	satisfied               bool
	presentButNotDominating bool
	missingFields           []string
	observed                []string
}

func evaluateRequiredCheck(req RequiredCheck, checks []evidence.Check) checkStatus {
	var status checkStatus
	fieldSet := map[string]struct{}{}

	for _, check := range checks {
		if check.Kind != req.Kind {
			continue
		}

		status.observed = appendObserved(status.observed, observedCheckLabel(check))
		if req.MustDominate && !check.DominatesTarget {
			status.presentButNotDominating = true
			continue
		}

		for _, field := range check.Fields {
			fieldSet[field] = struct{}{}
		}

		if len(req.RequiredFields) == 0 {
			status.satisfied = true
		}
	}

	if len(req.RequiredFields) == 0 {
		return status
	}

	status.missingFields = missingFields(req.RequiredFields, fieldSet)
	if len(status.missingFields) == 0 && len(fieldSet) > 0 {
		status.satisfied = true
	}
	return status
}

func appendObserved(observed []string, item string) []string {
	for _, existing := range observed {
		if existing == item {
			return observed
		}
	}
	return append(observed, item)
}

func observedCheckLabel(check evidence.Check) string {
	if len(check.Fields) == 0 {
		return check.Kind
	}
	return fmt.Sprintf("%s(fields: %s)", check.Kind, strings.Join(check.Fields, ", "))
}

func requirementLabel(kind string, fields []string) string {
	if len(fields) == 0 {
		return kind
	}
	return fmt.Sprintf("%s(fields: %s)", kind, strings.Join(fields, ", "))
}

func missingFields(required []string, present map[string]struct{}) []string {
	var missing []string
	for _, field := range required {
		if _, ok := present[field]; ok {
			continue
		}
		missing = append(missing, field)
	}
	return missing
}

func humanizeKind(kind string) string {
	return strings.ReplaceAll(kind, "_", " ")
}
