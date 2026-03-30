package rules

import (
	"os"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/evidence"
)

func TestEvaluateMissingDominatingCheck(t *testing.T) {
	rule := Rule{
		ID:           "TEE.PARAM_TYPES.MISSING_BEFORE_MEMREF_USE",
		TriggerKinds: []string{"memref_use"},
		RequiredChecks: []RequiredCheck{
			{Kind: "param_types_check", MustDominate: true},
		},
		LLMReviewRequired: true,
	}

	ev := evidence.Package{
		Metadata: map[string]string{"review_recommended": "false"},
		Candidate: evidence.Candidate{
			ID:            "cand-1",
			OperationKind: "memref_use",
		},
	}

	finding, ok := Evaluate(rule, ev)
	if !ok {
		t.Fatalf("expected a finding")
	}
	if finding.Status != "finding" {
		t.Fatalf("expected status finding, got %s", finding.Status)
	}
	if len(finding.MissingChecks) != 1 || finding.MissingChecks[0] != "param_types_check" {
		t.Fatalf("unexpected missing checks: %#v", finding.MissingChecks)
	}
}

func TestEvaluateNeedsReviewWhenConfigured(t *testing.T) {
	rule := Rule{
		ID:                "TEE.PARAM_TYPES.MISSING_BEFORE_MEMREF_USE",
		TriggerKinds:      []string{"memref_use"},
		LLMReviewRequired: true,
		RequiredChecks: []RequiredCheck{
			{Kind: "param_types_check", MustDominate: true},
		},
	}

	ev := evidence.Package{
		Metadata: map[string]string{"review_recommended": "true"},
		Candidate: evidence.Candidate{
			ID:            "cand-2",
			OperationKind: "memref_use",
		},
		Checks: []evidence.Check{
			{Kind: "param_types_check", DominatesTarget: false},
		},
	}

	finding, ok := Evaluate(rule, ev)
	if !ok {
		t.Fatalf("expected a finding")
	}
	if !finding.NeedsReview {
		t.Fatalf("expected finding to require review")
	}
	if finding.Status != "needs_review" {
		t.Fatalf("expected status needs_review, got %s", finding.Status)
	}
}

func TestEvaluateMissingRequiredFields(t *testing.T) {
	rule := Rule{
		ID:           "ATTESTATION.QE_IDENTITY.MISSING_BINDING_OR_VERIFICATION",
		TriggerKinds: []string{"attestation_verification_entry"},
		RequiredChecks: []RequiredCheck{
			{
				Kind:           "identity_policy_binding",
				MustDominate:   true,
				RequiredFields: []string{"mrsigner", "isvprodid", "miscselect_masked"},
			},
		},
	}

	ev := evidence.Package{
		Candidate: evidence.Candidate{
			ID:            "cand-3",
			OperationKind: "attestation_verification_entry",
			Function:      "verify",
		},
		Checks: []evidence.Check{
			{
				Kind:            "identity_policy_binding",
				DominatesTarget: true,
				Fields:          []string{"mrsigner", "isvprodid"},
			},
		},
	}

	finding, ok := Evaluate(rule, ev)
	if !ok {
		t.Fatalf("expected a finding")
	}
	if len(finding.MissingChecks) != 1 {
		t.Fatalf("unexpected missing checks: %#v", finding.MissingChecks)
	}
	want := "identity_policy_binding(fields: miscselect_masked)"
	if finding.MissingChecks[0] != want {
		t.Fatalf("expected %q, got %q", want, finding.MissingChecks[0])
	}
}

func TestEvaluateUnionsFieldsAcrossChecks(t *testing.T) {
	rule := Rule{
		ID:           "ATTESTATION.QE_IDENTITY.MISSING_BINDING_OR_VERIFICATION",
		TriggerKinds: []string{"attestation_verification_entry"},
		RequiredChecks: []RequiredCheck{
			{
				Kind:           "identity_policy_binding",
				MustDominate:   true,
				RequiredFields: []string{"mrsigner", "isvprodid", "miscselect_masked"},
			},
		},
	}

	ev := evidence.Package{
		Candidate: evidence.Candidate{
			ID:            "cand-4",
			OperationKind: "attestation_verification_entry",
		},
		Checks: []evidence.Check{
			{
				Kind:            "identity_policy_binding",
				DominatesTarget: true,
				Fields:          []string{"mrsigner"},
			},
			{
				Kind:            "identity_policy_binding",
				DominatesTarget: true,
				Fields:          []string{"isvprodid", "miscselect_masked"},
			},
		},
	}

	if _, ok := Evaluate(rule, ev); ok {
		t.Fatalf("did not expect a finding when required fields are satisfied across checks")
	}
}

func TestParseAttestationTemplateStrictly(t *testing.T) {
	data, err := os.ReadFile("/Users/pw0rld/Desktop/TEENET/TEECheck/tee-usage-scanner/rules/templates/attestation_qe_identity_template.json")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}

	rule, err := parseRule(data)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	if rule.ID != "ATTESTATION.QE_IDENTITY.MISSING_BINDING_OR_VERIFICATION" {
		t.Fatalf("unexpected rule id: %s", rule.ID)
	}
	if len(rule.RequiredChecks) != 3 {
		t.Fatalf("expected 3 required checks, got %d", len(rule.RequiredChecks))
	}
	if len(rule.LLMReviewQuestions) == 0 {
		t.Fatalf("expected template review questions to be preserved")
	}
}
