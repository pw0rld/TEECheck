package twe

import (
	"os"
	"path/filepath"
	"testing"
)

const validBinding = `
id: TWE-BIND-001
name: Unbound Attested Subject Authority
family: Binding
summary: Verifies a TEE artifact but grants authority to an unbound subject.
applicable_contexts: [worker_registration, key_release]
required_trustir: [claim_field, authority_subject]
allowed_enums:
  claim_field: [attested_public_key, runtime_public_key]
  authority_subject: [registered_worker, key_release_recipient]
codeql_modules:
  - binding/missing_subject_binding.ql
violation_condition: Authority granted without an accepted binding relation.
accepted_suppressors: [authority_subject_derived_from_claim, test_or_dev_only]
fixtures: [TWE-BIND-0001]
`

func writeCatalog(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadValidCatalog(t *testing.T) {
	dir := writeCatalog(t, map[string]string{"binding.yml": validBinding})
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("len=%d want 1", c.Len())
	}
	e, ok := c.Get("TWE-BIND-001")
	if !ok {
		t.Fatal("entry not found by id")
	}
	if e.Family != FamilyBinding {
		t.Fatalf("family=%q", e.Family)
	}
	if len(e.AllowedEnums["claim_field"]) != 2 {
		t.Fatalf("allowed_enums not parsed: %+v", e.AllowedEnums)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"missing id": `
name: X
family: Binding
summary: s
applicable_contexts: [c]
required_trustir: [r]
codeql_modules: [m.ql]
violation_condition: v`,
		"bad family": `
id: T-1
name: X
family: Nope
summary: s
applicable_contexts: [c]
required_trustir: [r]
codeql_modules: [m.ql]
violation_condition: v`,
		"enum role not required": `
id: T-2
name: X
family: Guard
summary: s
applicable_contexts: [c]
required_trustir: [role_a]
allowed_enums:
  role_b: [x]
codeql_modules: [m.ql]
violation_condition: v`,
		"empty applicable_contexts": `
id: T-3
name: X
family: Guard
summary: s
applicable_contexts: []
required_trustir: [r]
codeql_modules: [m.ql]
violation_condition: v`,
		"no codeql modules": `
id: T-4
name: X
family: Guard
summary: s
applicable_contexts: [c]
required_trustir: [r]
codeql_modules: []
violation_condition: v`,
		"unknown field": `
id: T-5
name: X
family: Guard
summary: s
applicable_contexts: [c]
required_trustir: [r]
codeql_modules: [m.ql]
violation_condition: v
bogus_field: 1`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeCatalog(t, map[string]string{"c.yml": body})
			if _, err := Load(dir); err == nil {
				t.Fatalf("expected load to reject %q", name)
			}
		})
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	dir := writeCatalog(t, map[string]string{
		"a.yml": validBinding,
		"b.yml": validBinding,
	})
	if _, err := Load(dir); err == nil {
		t.Fatal("expected duplicate id to be rejected")
	}
}

func TestByContext(t *testing.T) {
	dir := writeCatalog(t, map[string]string{"binding.yml": validBinding})
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ByContext("worker_registration"); len(got) != 1 {
		t.Fatalf("worker_registration matched %d", len(got))
	}
	if got := c.ByContext("nonexistent_context"); len(got) != 0 {
		t.Fatalf("unexpected match: %d", len(got))
	}
}

func TestValidateCandidate(t *testing.T) {
	dir := writeCatalog(t, map[string]string{"binding.yml": validBinding})
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	good := TrustIRCandidate{
		TWEID: "TWE-BIND-001",
		Roles: map[string]RoleCandidate{
			"claim_field":       {Enum: "attested_public_key", Loc: Loc{Path: "a.rs", Line: 1}},
			"authority_subject": {Enum: "registered_worker", Loc: Loc{Path: "a.rs", Line: 2}},
		},
	}
	if err := c.ValidateCandidate(good); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}

	missing := good
	missing.Roles = map[string]RoleCandidate{"claim_field": good.Roles["claim_field"]}
	if err := c.ValidateCandidate(missing); err == nil {
		t.Fatal("expected missing-role rejection")
	}

	badEnum := TrustIRCandidate{
		TWEID: "TWE-BIND-001",
		Roles: map[string]RoleCandidate{
			"claim_field":       {Enum: "not_allowed"},
			"authority_subject": {Enum: "registered_worker"},
		},
	}
	if err := c.ValidateCandidate(badEnum); err == nil {
		t.Fatal("expected bad-enum rejection")
	}

	if err := c.ValidateCandidate(TrustIRCandidate{TWEID: "nope"}); err == nil {
		t.Fatal("expected unknown twe_id rejection")
	}
}

// TestSeedCatalogLoads keeps the shipped catalog honest: the real
// knowledge/twe/ directory must always load and validate.
func TestSeedCatalogLoads(t *testing.T) {
	dir := filepath.Join("..", "..", "knowledge", "twe")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("no seed catalog yet")
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("seed catalog failed to load: %v", err)
	}
	if c.Len() == 0 {
		t.Fatal("seed catalog is empty")
	}
	for _, e := range c.All() {
		if len(e.Fixtures) == 0 {
			t.Errorf("%s has no fixtures linked", e.ID)
		}
	}
}
