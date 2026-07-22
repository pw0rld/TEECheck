package twecontext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPlaybook = `schema_version: teecheck.twe_playbook.v1
id: TWE-STATE-TEST
name: Test State Weakness
family: State
scenario: A replayed state changes a security decision.
attacker_capabilities: [replay_state]
look_for: [restore_path]
investigation_steps: [trace_restore]
required_evidence: [reachable_restore]
common_defenses: [monotonic_counter]
common_false_positives: [cache_only]
related_twes: []
trustir_hints: [trace_restore_to_authority]
`

func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	content := validPlaybook + "unknown_field: true\n"
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("Load() error = %v, want unknown-field rejection", err)
	}
}

func TestCompileIsStableAndSortedByID(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	first := strings.Replace(validPlaybook, "TWE-STATE-TEST", "TWE-STATE-A", 1)
	second := strings.Replace(validPlaybook, "TWE-STATE-TEST", "TWE-STATE-Z", 1)
	writeFixture(t, dirA, "z.yml", second)
	writeFixture(t, dirA, "a.yml", first)
	writeFixture(t, dirB, "one.yml", first)
	writeFixture(t, dirB, "two.yml", second)

	catalogA, err := Load(dirA)
	if err != nil {
		t.Fatal(err)
	}
	catalogB, err := Load(dirB)
	if err != nil {
		t.Fatal(err)
	}
	compiledA, err := catalogA.Compile()
	if err != nil {
		t.Fatal(err)
	}
	compiledB, err := catalogB.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiledA.Text != compiledB.Text {
		t.Fatal("compiled context depends on file names or directory order")
	}
	if compiledA.Manifest.CatalogSHA256 != compiledB.Manifest.CatalogSHA256 ||
		compiledA.Manifest.ContextSHA256 != compiledB.Manifest.ContextSHA256 {
		t.Fatal("stable catalogs produced different hashes")
	}
	if got := compiledA.Manifest.TWEIDs; len(got) != 2 || got[0] != "TWE-STATE-A" || got[1] != "TWE-STATE-Z" {
		t.Fatalf("TWEIDs = %v, want sorted IDs", got)
	}
	if strings.Index(compiledA.Text, "TWE-STATE-A") > strings.Index(compiledA.Text, "TWE-STATE-Z") {
		t.Fatal("compiled context is not sorted by TWE id")
	}
}

func TestAllDoesNotExposeCatalogForMutation(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "test.yml", validPlaybook)
	catalog, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := catalog.Compile()
	if err != nil {
		t.Fatal(err)
	}
	copy := catalog.All()
	copy[0].Name = "mutated"
	copy[0].LookFor[0] = "mutated"
	after, err := catalog.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if before.Text != after.Text ||
		before.Manifest.CatalogSHA256 != after.Manifest.CatalogSHA256 ||
		before.Manifest.ContextSHA256 != after.Manifest.ContextSHA256 {
		t.Fatal("All() exposed mutable catalog state")
	}
}

func TestShippedRollbackPlaybook(t *testing.T) {
	dir := filepath.Join("..", "..", "knowledge", "twe", "playbooks")
	catalog, err := Load(dir)
	if err != nil {
		t.Fatalf("load shipped playbooks: %v", err)
	}
	compiled, err := catalog.Compile()
	if err != nil {
		t.Fatalf("compile shipped playbooks: %v", err)
	}
	if len(compiled.Manifest.TWEIDs) != 1 || compiled.Manifest.TWEIDs[0] != "TWE-STATE-001" {
		t.Fatalf("shipped TWE IDs = %v", compiled.Manifest.TWEIDs)
	}
	// Both rollback attack shapes (§20.2) must show up in the compiled
	// context: the host replaying persisted state wholesale, and the
	// version/epoch failing to propagate so the guard runs but is inert
	// (the CVE-2026-44362 shape, §8.9).
	for _, required := range []string{
		"all_host_to_tee_and_tee_to_host_interfaces",
		"trace_version_epoch_or_counter_fields_to_the_runtime_object",
		"test_whether_state_and_its_freshness_value_can_be_rolled_back_together",
		"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input",
		"security_relevant_effect_after_stale_state_is_accepted",
		"correctly_propagated_signed_version_to_rollback_database",
	} {
		if !strings.Contains(compiled.Text, required) {
			t.Errorf("compiled rollback context is missing %q", required)
		}
	}
	if len(compiled.Manifest.CatalogSHA256) != 64 || len(compiled.Manifest.ContextSHA256) != 64 {
		t.Fatal("manifest hashes are not SHA-256 hex digests")
	}
	if compiled.ContextTokenEstimate <= 0 {
		t.Fatal("ContextTokenEstimate was not computed")
	}
	if compiled.ContextTokenEstimate >= maxPlaybookContextTokens {
		t.Fatalf("shipped rollback playbook (~%d tokens) does not leave headroom under the %d-token ceiling",
			compiled.ContextTokenEstimate, maxPlaybookContextTokens)
	}
}

// TestCompileFailsWhenPlaybookExceedsTokenBudget proves the token ceiling
// (§11.1, §20.4) fails compilation instead of truncating the oversized
// playbook — the only failure mode that keeps the injected context faithful
// to what is actually on disk.
func TestCompileFailsWhenPlaybookExceedsTokenBudget(t *testing.T) {
	dir := t.TempDir()
	// maxPlaybookContextTokens is a chars/4 estimate, so a scenario padded
	// well past 4*maxPlaybookContextTokens characters guarantees the block
	// exceeds the ceiling regardless of the fixed labels/newlines around it.
	oversized := strings.Replace(
		validPlaybook,
		"scenario: A replayed state changes a security decision.",
		"scenario: "+strings.Repeat("A replayed state changes a security decision. ", 200),
		1,
	)
	writeFixture(t, dir, "oversized.yml", oversized)

	catalog, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = catalog.Compile()
	if err == nil {
		t.Fatal("expected Compile to fail closed on an oversized playbook, not truncate it")
	}
	if !strings.Contains(err.Error(), "TWE-STATE-TEST") || !strings.Contains(err.Error(), "compile-time ceiling") {
		t.Fatalf("Compile error = %v, want it to name the offending playbook and the ceiling", err)
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
