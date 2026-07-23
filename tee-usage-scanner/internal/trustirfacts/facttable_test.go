package trustirfacts

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

func TestFactTableEmpty(t *testing.T) {
	if !(FactTable{}).Empty() {
		t.Error("zero-value FactTable should be Empty")
	}
	nonEmpty := FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "r"}}}
	if nonEmpty.Empty() {
		t.Error("table with a clause should not be Empty")
	}
}

func TestFactTableRender_EmptyPredicatesAreNone(t *testing.T) {
	out := FactTable{}.Render()
	if !strings.Contains(out, "import cpp") {
		t.Error("rendered qll must import cpp")
	}
	if !strings.Contains(out, "module GeneratedTrustFacts {") {
		t.Error("rendered qll must declare the GeneratedTrustFacts module")
	}
	for _, pred := range []string{"isClaimProducer", "rollbackVersionField", "producedStruct", "isRollbackAuthority", "hasSuppressor"} {
		if !strings.Contains(out, "predicate "+pred) {
			t.Errorf("rendered qll missing predicate %s", pred)
		}
	}
	// An empty table renders every predicate body as none() — no clause is
	// silently fabricated for a table with no facts (§23.4.3).
	if got := strings.Count(out, "none()"); got != 5 {
		t.Errorf("none() count = %d, want 5 (one per predicate)", got)
	}
}

func TestFactTableRender_ClausesEmbedRealNames(t *testing.T) {
	table := FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		ProducedStructs:     []string{"shdr_pub_key"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	}
	out := table.Render()

	for _, want := range []string{
		`f.getName() = "shdr_load_pub_key" and role = "security_version"`,
		`field = "version"`,
		`typeName = "shdr_pub_key"`,
		`c.getTarget().getName() = "check_update_version" and kind = "state_restore_acceptance"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered qll missing clause %q\n---\n%s", want, out)
		}
	}
	// hasSuppressor stays none() in this slice regardless of table content.
	if !strings.Contains(out, "predicate hasSuppressor(Function f, string suppressor) { none() }") {
		t.Error("hasSuppressor must remain none() (annotation pipeline deferred, §23.2)")
	}
}

func TestFactTableRender_EscapesQuotes(t *testing.T) {
	table := FactTable{RollbackFields: []string{`weird"field`}}
	out := table.Render()
	if !strings.Contains(out, `field = "weird\"field"`) {
		t.Errorf("expected escaped quote in rendered clause, got:\n%s", out)
	}
}

func TestNormalizeRepo(t *testing.T) {
	want := "github.com/op-tee/optee_os"
	inputs := []string{
		"https://github.com/OP-TEE/optee_os",
		"https://github.com/OP-TEE/optee_os/",
		"https://github.com/OP-TEE/optee_os.git",
		"http://github.com/OP-TEE/optee_os.git",
		"git@github.com:OP-TEE/optee_os.git",
	}
	for _, in := range inputs {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFactTableFor_KnownAndUnknownRepository(t *testing.T) {
	if _, ok := factTableFor("https://github.com/OP-TEE/optee_os.git"); !ok {
		t.Fatal("expected a registered fact table for the OP-TEE repository")
	}
	if _, ok := factTableFor("https://github.com/some/unrelated-repo"); ok {
		t.Fatal("expected no fact table for an unregistered repository")
	}
}

// TestKnownFactTablesUseRegisteredEnumValues loads the real
// enum_registry.yml — the single fact vocabulary (§23.4.2) — and checks that
// every role/kind value the deterministic fixture registry uses is a member
// of the right category. This is the §23 acceptance criterion "role 枚举与
// enum_registry.yml 一致性有测试保证", and it is a deliberate correction of
// the spike pack, which used ad hoc strings not in the registry (see
// facttable.go's doc comment on knownFactTables).
func TestKnownFactTablesUseRegisteredEnumValues(t *testing.T) {
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "enum_registry.yml")
	registry, err := twe.LoadEnumRegistry(path)
	if err != nil {
		t.Fatalf("load enum registry: %v", err)
	}

	claimRoles := memberSet(registry["claim_field_role"])
	authorityKinds := memberSet(registry["authority_kind"])
	if len(claimRoles) == 0 || len(authorityKinds) == 0 {
		t.Fatal("registry categories claim_field_role/authority_kind must be non-empty")
	}

	for repo, table := range knownFactTables {
		for _, f := range table.ClaimProducers {
			if !claimRoles[f.Role] {
				t.Errorf("%s: isClaimProducer role %q is not in enum_registry.yml's claim_field_role", repo, f.Role)
			}
		}
		for _, f := range table.RollbackAuthorities {
			if !authorityKinds[f.Kind] {
				t.Errorf("%s: isRollbackAuthority kind %q is not in enum_registry.yml's authority_kind", repo, f.Kind)
			}
		}
	}
}

func memberSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}
