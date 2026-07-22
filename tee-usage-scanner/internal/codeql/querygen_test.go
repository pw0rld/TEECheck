package codeql

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

func bindingCandidate() twe.TrustIRCandidate {
	return twe.TrustIRCandidate{
		TWEID:  "TWE-BIND-001",
		SiteID: "bind001-registry-10",
		Roles: map[string]twe.RoleCandidate{
			"claim_field":       {Enum: "attested_public_key", Loc: twe.Loc{Path: "src/registry.rs", Line: 9, Symbol: "report.pubkey"}},
			"authority_subject": {Enum: "registered_worker", Loc: twe.Loc{Path: "src/registry.rs", Line: 10, Symbol: "pubkey"}},
		},
	}
}

func TestGenerateBindingQuery(t *testing.T) {
	q, err := GenerateBindingQuery(bindingCandidate())
	if err != nil {
		t.Fatal(err)
	}
	// the attested variable derives from the claim symbol, not hardcoded
	if !strings.Contains(q, `nr.getText() = "report"`) {
		t.Errorf("query does not check the derived attested variable:\n%s", q)
	}
	// the authority function is pinned by the TrustIR location
	if !strings.Contains(q, `getBaseName() = "registry.rs"`) || !strings.Contains(q, "getStartLine() = 10") {
		t.Errorf("query does not pin the authority location:\n%s", q)
	}
	if !strings.Contains(q, "import rust") || !strings.Contains(q, "@kind problem") {
		t.Errorf("query missing preamble:\n%s", q)
	}
}

func TestGenerateConfigQuery(t *testing.T) {
	cand := twe.TrustIRCandidate{
		TWEID:  "TWE-CONFIG-001",
		SiteID: "cfg001-attest",
		Roles: map[string]twe.RoleCandidate{
			"mode_selector":   {Enum: "simulation_mode", Loc: twe.Loc{Path: "src/attest.rs", Line: 19, Symbol: "Mode::Simulated"}},
			"authority_point": {Enum: "attestation_acceptance", Loc: twe.Loc{Path: "src/attest.rs", Line: 20, Symbol: "Ok"}},
		},
	}
	q, err := GenerateConfigQuery(cand)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, "getStartLine() = 19") || !strings.Contains(q, `getBaseName() = "attest.rs"`) {
		t.Errorf("query does not pin the mode selector:\n%s", q)
	}
	if !strings.Contains(q, `ok.getText() = "Ok"`) {
		t.Errorf("query does not check for an acceptance:\n%s", q)
	}
}

func TestGenerateConfigQueryMissingRole(t *testing.T) {
	cand := twe.TrustIRCandidate{TWEID: "TWE-CONFIG-001", Roles: map[string]twe.RoleCandidate{}}
	if _, err := GenerateConfigQuery(cand); err == nil {
		t.Fatal("expected error when mode_selector role is absent")
	}
}

func TestGenerateBindingQueryMissingRole(t *testing.T) {
	cand := bindingCandidate()
	delete(cand.Roles, "authority_subject")
	if _, err := GenerateBindingQuery(cand); err == nil {
		t.Fatal("expected error when authority_subject role is absent")
	}
}

func TestAttestedVarName(t *testing.T) {
	cases := map[string]string{
		"report.pubkey":   "report",
		"quote.report.mr": "quote",
		"_report":         "_report",
		"pubkey":          "pubkey",
		"":                "",
	}
	for in, want := range cases {
		if got := attestedVarName(in); got != want {
			t.Errorf("attestedVarName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	if got := sanitizeID("bind001-Registry_42"); got != "bind001-registry-42" {
		t.Errorf("sanitizeID=%q", got)
	}
}
