package twe

import (
	"os"
	"path/filepath"
	"testing"
)

const validDefinitionCatalog = `twe:
  - id: TWE-BIND-001
    family: Binding
    name: Unbound Attested Subject Authority
    query_modules: [binding/MissingSubjectBinding.ql]
    required_trustir: [claim_field, authority_subject]
`

func writeYAML(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefinitionsValid(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "catalog.yml", validDefinitionCatalog)
	defs, err := LoadDefinitions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 || defs[0].ID != "TWE-BIND-001" {
		t.Fatalf("defs = %+v", defs)
	}
	if defs[0].Family != FamilyBinding {
		t.Fatalf("family = %q", defs[0].Family)
	}
}

func TestLoadDefinitionsRejects(t *testing.T) {
	cases := map[string]string{
		"empty catalog":       `twe: []`,
		"missing id":          "twe:\n  - family: Binding\n    name: X\n    query_modules: [m.ql]\n    required_trustir: [r]\n",
		"bad id format":       "twe:\n  - id: bind-001\n    family: Binding\n    name: X\n    query_modules: [m.ql]\n    required_trustir: [r]\n",
		"bad family":          "twe:\n  - id: TWE-X-001\n    family: Nope\n    name: X\n    query_modules: [m.ql]\n    required_trustir: [r]\n",
		"missing name":        "twe:\n  - id: TWE-X-001\n    family: Binding\n    query_modules: [m.ql]\n    required_trustir: [r]\n",
		"no query modules":    "twe:\n  - id: TWE-X-001\n    family: Binding\n    name: X\n    query_modules: []\n    required_trustir: [r]\n",
		"no required trustir": "twe:\n  - id: TWE-X-001\n    family: Binding\n    name: X\n    query_modules: [m.ql]\n    required_trustir: []\n",
		"duplicate role":      "twe:\n  - id: TWE-X-001\n    family: Binding\n    name: X\n    query_modules: [m.ql]\n    required_trustir: [r, r]\n",
		"duplicate id":        "twe:\n  - {id: TWE-X-001, family: Binding, name: X, query_modules: [m.ql], required_trustir: [r]}\n  - {id: TWE-X-001, family: Binding, name: Y, query_modules: [m.ql], required_trustir: [r]}\n",
		"unknown field":       "twe:\n  - id: TWE-X-001\n    family: Binding\n    name: X\n    query_modules: [m.ql]\n    required_trustir: [r]\n    bogus: 1\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeYAML(t, dir, "catalog.yml", body)
			if _, err := LoadDefinitions(path); err == nil {
				t.Fatalf("expected LoadDefinitions to reject %q", name)
			}
		})
	}
}

// TestShippedDefinitionCatalog is the "16 TWE, seven families, full
// correspondence" check §20's acceptance criteria and test list require: the
// shipped catalog must have exactly 16 unique-id entries, the exact
// per-family counts §20.1's table lists, and use every family types.go
// declares — no eighth family, no missing one.
func TestShippedDefinitionCatalog(t *testing.T) {
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "catalog.yml")
	defs, err := LoadDefinitions(path)
	if err != nil {
		t.Fatalf("load shipped catalog: %v", err)
	}
	if len(defs) != 16 {
		t.Fatalf("len(defs) = %d, want 16", len(defs))
	}

	seenIDs := make(map[string]bool, len(defs))
	countByFamily := make(map[Family]int)
	for _, d := range defs {
		if seenIDs[d.ID] {
			t.Errorf("duplicate id %q in shipped catalog", d.ID)
		}
		seenIDs[d.ID] = true
		countByFamily[d.Family]++
	}

	wantCounts := map[Family]int{
		FamilyFlow:    2,
		FamilyGuard:   3,
		FamilyBinding: 3,
		FamilyState:   2,
		FamilyConfig:  2,
		FamilyDesign:  2,
		FamilyLeakage: 2,
	}
	if len(countByFamily) != len(ValidFamilies) {
		t.Fatalf("shipped catalog uses %d families, want all %d from internal/twe.Family", len(countByFamily), len(ValidFamilies))
	}
	for family, want := range wantCounts {
		if got := countByFamily[family]; got != want {
			t.Errorf("family %s has %d entries, want %d", family, got, want)
		}
	}
}

// TestOldEntriesReconcileWithShippedDefinitions proves the migration did not
// leave two disagreeing definitions of the same TWE: every legacy Entry under
// knowledge/twe/ (binding.yml, config.yml — still the executable format the
// retired query generator reads) names a TWE id that also exists, with the
// same family, in the new migrated definition catalog.
func TestOldEntriesReconcileWithShippedDefinitions(t *testing.T) {
	entryCatalog, err := Load(filepath.Join("..", "..", "knowledge", "twe"))
	if err != nil {
		t.Fatalf("load legacy Entry catalog: %v", err)
	}
	defs, err := LoadDefinitions(filepath.Join("..", "..", "knowledge", "twe", "definitions", "catalog.yml"))
	if err != nil {
		t.Fatalf("load shipped definition catalog: %v", err)
	}
	byID := make(map[string]Definition, len(defs))
	for _, d := range defs {
		byID[d.ID] = d
	}
	for _, e := range entryCatalog.All() {
		d, ok := byID[e.ID]
		if !ok {
			t.Errorf("legacy Entry %s has no corresponding definition in the migrated catalog", e.ID)
			continue
		}
		if d.Family != e.Family {
			t.Errorf("%s: legacy Entry family %s disagrees with definition family %s", e.ID, e.Family, d.Family)
		}
	}
}

func TestLoadTaxonomyValid(t *testing.T) {
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "taxonomy.yml")
	tax, err := LoadTaxonomy(path)
	if err != nil {
		t.Fatalf("load shipped taxonomy: %v", err)
	}
	if len(tax.Families) != len(ValidFamilies) {
		t.Fatalf("taxonomy has %d families, want %d", len(tax.Families), len(ValidFamilies))
	}
	for family := range ValidFamilies {
		if _, ok := tax.Families[family]; !ok {
			t.Errorf("taxonomy is missing family %s declared in internal/twe.Family", family)
		}
	}
}

func TestLoadTaxonomyRejectsFamilyMismatch(t *testing.T) {
	dir := t.TempDir()
	// Only six of the seven families, plus one internal/twe.Family does not
	// declare — this must fail on both sides of the correspondence check.
	body := `families:
  Flow: {name: Trust Boundary Flow, definition: d, codeql_strategy: s}
  Guard: {name: Verification Gap, definition: d, codeql_strategy: s}
  Binding: {name: Binding Weakness, definition: d, codeql_strategy: s}
  State: {name: State Continuity, definition: d, codeql_strategy: s}
  Config: {name: Configuration Integrity, definition: d, codeql_strategy: s}
  Design: {name: Design Appropriateness, definition: d, codeql_strategy: s}
  Rollback: {name: Not A Real Family, definition: d, codeql_strategy: s}
tee_dimensions: [incorrect_usage]
trust_contexts: [key_release]
`
	path := writeYAML(t, dir, "taxonomy.yml", body)
	if _, err := LoadTaxonomy(path); err == nil {
		t.Fatal("expected family mismatch to be rejected")
	}
}

func TestLoadEnumRegistryValid(t *testing.T) {
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "enum_registry.yml")
	reg, err := LoadEnumRegistry(path)
	if err != nil {
		t.Fatalf("load shipped enum registry: %v", err)
	}
	values, ok := reg["state_object_kind"]
	if !ok {
		t.Fatal("enum registry is missing state_object_kind")
	}
	found := false
	for _, v := range values {
		if v == "sealed_blob" {
			found = true
		}
	}
	if !found {
		t.Fatal("state_object_kind is missing sealed_blob")
	}
}

func TestLoadEnumRegistryRejectsDuplicateValue(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "enum_registry.yml", "some_kind: [a, b, a]\n")
	if _, err := LoadEnumRegistry(path); err == nil {
		t.Fatal("expected duplicate value to be rejected")
	}
}

func TestLoadExclusionRulesValid(t *testing.T) {
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "exclusion.yml")
	rules, err := LoadExclusionRules(path)
	if err != nil {
		t.Fatalf("load shipped exclusion rules: %v", err)
	}
	found := false
	for _, glob := range rules.DenyGlobs {
		if glob == "**/vendor/**" {
			found = true
		}
	}
	if !found {
		t.Fatal("deny_globs is missing **/vendor/**")
	}
}

func TestLoadExclusionRulesRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "exclusion.yml", "deny_globs: []\n")
	if _, err := LoadExclusionRules(path); err == nil {
		t.Fatal("expected empty deny_globs to be rejected")
	}
}

func TestExclusionRulesMatch(t *testing.T) {
	rules := ExclusionRules{DenyGlobs: []string{"**/vendor/**", "**/*.pb.go", "**/testdata/**"}}
	cases := []struct {
		rel  string
		want bool
	}{
		{"core/tee/tee_svc.c", false},
		{"third_party/vendor/openssl/rsa.c", true},
		{"vendor/github.com/foo/bar/baz.go", true},
		{"api/service.pb.go", true},
		{"internal/preprocessor/testdata/fixture.rs", true},
		{"internal/preprocessor/run.go", false},
	}
	for _, tc := range cases {
		if got := rules.Match(tc.rel); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}
