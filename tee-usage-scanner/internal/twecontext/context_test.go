package twecontext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
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
	// The catalog grows as playbooks are authored, so assert this playbook is
	// shipped rather than that it is the only one.
	var rollback Playbook
	for _, p := range catalog.playbooks {
		if p.ID == "TWE-STATE-001" {
			rollback = p
		}
	}
	if rollback.ID != "TWE-STATE-001" {
		t.Fatalf("shipped TWE IDs = %v, want TWE-STATE-001 among them", compiled.Manifest.TWEIDs)
	}
	// Compile now renders the brief tier: the look_for signal that lets an
	// agent judge relevance must show up in the compiled context.
	if !strings.Contains(compiled.Text, "all_host_to_tee_and_tee_to_host_interfaces") {
		t.Errorf("compiled rollback brief context is missing look_for content")
	}
	// The investigation method belongs to the detail tier only — it must NOT
	// be present in the always-injected brief compiled by Compile().
	for _, detailOnly := range []string{
		"trace_version_epoch_or_counter_fields_to_the_runtime_object",
		"test_whether_state_and_its_freshness_value_can_be_rolled_back_together",
		"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input",
		"security_relevant_effect_after_stale_state_is_accepted",
		"correctly_propagated_signed_version_to_rollback_database",
	} {
		if strings.Contains(compiled.Text, detailOnly) {
			t.Errorf("compiled rollback brief context must not contain detail-tier content %q", detailOnly)
		}
	}
	if len(compiled.Manifest.CatalogSHA256) != 64 || len(compiled.Manifest.ContextSHA256) != 64 {
		t.Fatal("manifest hashes are not SHA-256 hex digests")
	}
	if compiled.ContextTokenEstimate <= 0 {
		t.Fatal("ContextTokenEstimate was not computed")
	}
	// Measure the playbook's own brief block, not the whole compiled
	// document (which also carries the fixed contextHeader) — that is what
	// Compile()'s per-playbook ceiling actually enforces.
	if briefTokens := estimateTokens(compileBriefBlock(rollback)); briefTokens >= maxBriefContextTokens {
		t.Fatalf("shipped rollback playbook brief (~%d tokens) does not leave headroom under the %d-token ceiling",
			briefTokens, maxBriefContextTokens)
	}

	// Both rollback attack shapes (§20.2) must show up in the on-demand
	// detail tier: the host replaying persisted state wholesale, and the
	// version/epoch failing to propagate so the guard runs but is inert
	// (the CVE-2026-44362 shape, §8.9).
	detail, ok := catalog.Detail("TWE-STATE-001")
	if !ok {
		t.Fatal("expected a Detail hit for the shipped TWE-STATE-001 playbook")
	}
	for _, required := range []string{
		"all_host_to_tee_and_tee_to_host_interfaces",
		"trace_version_epoch_or_counter_fields_to_the_runtime_object",
		"test_whether_state_and_its_freshness_value_can_be_rolled_back_together",
		"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input",
		"security_relevant_effect_after_stale_state_is_accepted",
		"correctly_propagated_signed_version_to_rollback_database",
	} {
		if !strings.Contains(detail, required) {
			t.Errorf("detail rollback context is missing %q", required)
		}
	}
	if detailTokens := estimateTokens(detail); detailTokens >= maxDetailContextTokens {
		t.Fatalf("shipped rollback playbook detail (~%d tokens) does not leave headroom under the %d-token ceiling",
			detailTokens, maxDetailContextTokens)
	}
}

func TestShippedFlowPlaybook(t *testing.T) {
	dir := filepath.Join("..", "..", "knowledge", "twe", "playbooks")
	catalog, err := Load(dir)
	if err != nil {
		t.Fatalf("load shipped playbooks: %v", err)
	}
	compiled, err := catalog.Compile()
	if err != nil {
		t.Fatalf("compile shipped playbooks: %v", err)
	}
	// The catalog grows as playbooks are authored, so assert this playbook is
	// shipped rather than that it is the only one. This is the guard against
	// someone deleting the flow.yml deliverable outright.
	var flow Playbook
	for _, p := range catalog.playbooks {
		if p.ID == "TWE-FLOW-001" {
			flow = p
		}
	}
	if flow.ID != "TWE-FLOW-001" {
		t.Fatalf("shipped TWE IDs = %v, want TWE-FLOW-001 among them", compiled.Manifest.TWEIDs)
	}
	// Compile now renders the brief tier: a look_for signal that lets an
	// agent judge relevance must show up in the compiled context.
	if !strings.Contains(compiled.Text, "host_supplied_offsets_sizes_counts_indices_or_pointers_reaching_a_privileged_operation") {
		t.Errorf("compiled flow brief context is missing look_for content")
	}
	// A detail-only field label must NOT be present in the always-injected
	// brief compiled by Compile(), even though it IS present in the on-demand
	// detail tier below — this is the tier-separation guarantee.
	if strings.Contains(compiled.Text, "False positives:") {
		t.Errorf("compiled flow brief context must not contain the detail-tier field label %q", "False positives:")
	}
	// Measure the playbook's own brief block, not the whole compiled
	// document (which also carries the fixed contextHeader) — that is what
	// Compile()'s per-playbook ceiling actually enforces. Flow's brief is
	// close to the ceiling (~239 of 250 tokens), so assert against the
	// ceiling itself rather than a tight hand-picked number that would break
	// on any wording change.
	if briefTokens := estimateTokens(compileBriefBlock(flow)); briefTokens > maxBriefContextTokens {
		t.Fatalf("shipped flow playbook brief (~%d tokens) exceeds the %d-token ceiling",
			briefTokens, maxBriefContextTokens)
	}

	detail, ok := catalog.Detail("TWE-FLOW-001")
	if !ok {
		t.Fatal("expected a Detail hit for the shipped TWE-FLOW-001 playbook")
	}
	if !strings.Contains(detail, "False positives:") {
		t.Errorf("detail flow context is missing the %q field label", "False positives:")
	}
	if detailTokens := estimateTokens(detail); detailTokens > maxDetailContextTokens {
		t.Fatalf("shipped flow playbook detail (~%d tokens) exceeds the %d-token ceiling",
			detailTokens, maxDetailContextTokens)
	}
}

// TestCompileFailsWhenPlaybookExceedsTokenBudget proves the token ceiling
// (§11.1, §20.4) fails compilation instead of truncating the oversized
// playbook — the only failure mode that keeps the injected context faithful
// to what is actually on disk.
func TestCompileFailsWhenPlaybookExceedsTokenBudget(t *testing.T) {
	dir := t.TempDir()
	// maxBriefContextTokens is a chars/4 estimate, so a scenario padded well
	// past 4*maxBriefContextTokens characters guarantees the brief block
	// exceeds the ceiling regardless of the fixed labels/newlines around it.
	// (The scenario alone stays under maxDetailContextTokens, so Load/Validate
	// still succeeds — only Compile's brief-tier ceiling fails closed here.)
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

func testPlaybook() Playbook {
	return Playbook{
		SchemaVersion:        SchemaVersion,
		ID:                   "TWE-TEST-001",
		Name:                 "Test Weakness",
		Family:               twe.FamilyState,
		Scenario:             "A scenario sentence.",
		AttackerCapabilities: []string{"cap_one"},
		LookFor:              []string{"look_one"},
		InvestigationSteps:   []string{"step_one"},
		RequiredEvidence:     []string{"evidence_one"},
		CommonDefenses:       []string{"defense_one"},
		CommonFalsePositives: []string{"fp_one"},
		RelatedTWEs:          []string{"TWE-TEST-002"},
		TrustIRHints:         []string{"hint_one"},
	}
}

// The brief tier is what every agent carries, so it must contain only the
// two fields an agent needs to judge relevance — carrying the investigation
// method in the always-injected tier is the cost problem this change exists
// to fix.
func TestCompileBriefBlock_OnlyScenarioAndLookFor(t *testing.T) {
	got := compileBriefBlock(testPlaybook())
	for _, want := range []string{"TWE-TEST-001", "Test Weakness", "Scenario:", "Look for:"} {
		if !strings.Contains(got, want) {
			t.Errorf("brief missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"Investigate:", "Evidence required:", "Defenses:", "False positives:", "Attacker:", "Tool hints:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("brief must not contain %q (detail-tier field):\n%s", unwanted, got)
		}
	}
}

func TestCompileDetailBlock_CarriesEveryField(t *testing.T) {
	got := compileDetailBlock(testPlaybook())
	for _, want := range []string{"Scenario:", "Attacker:", "Look for:", "Investigate:", "Evidence required:", "Defenses:", "False positives:", "Related:", "Tool hints:"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail missing %q:\n%s", want, got)
		}
	}
}

// Fail closed, and name the offending playbook: a truncated playbook would
// silently give an agent half a method.
func TestCompile_FailsClosedOnOversizedBrief(t *testing.T) {
	p := testPlaybook()
	p.Scenario = strings.Repeat("word ", 400) // ~500 tokens, well over the 250 brief ceiling
	c := &Catalog{playbooks: []Playbook{p}}
	_, err := c.Compile()
	if err == nil {
		t.Fatal("expected Compile to fail closed on an oversized brief")
	}
	if !strings.Contains(err.Error(), "TWE-TEST-001") {
		t.Errorf("error must name the offending playbook, got: %v", err)
	}
}

func TestValidate_FailsClosedOnOversizedDetail(t *testing.T) {
	p := testPlaybook()
	p.InvestigationSteps = []string{strings.Repeat("step ", 3000)} // ~3750 tokens, over the 3000 detail ceiling
	err := p.Validate()
	if err == nil {
		t.Fatal("expected Validate to reject an oversized detail block")
	}
	if !strings.Contains(err.Error(), "TWE-TEST-001") {
		t.Errorf("error must name the offending playbook, got: %v", err)
	}
}

func TestCatalogDetail_HitAndMiss(t *testing.T) {
	c := &Catalog{playbooks: []Playbook{testPlaybook()}}
	text, ok := c.Detail("TWE-TEST-001")
	if !ok {
		t.Fatal("expected a hit for TWE-TEST-001")
	}
	if !strings.Contains(text, "Investigate:") {
		t.Errorf("Detail must return the full block, got:\n%s", text)
	}
	if _, ok := c.Detail("TWE-NOPE-999"); ok {
		t.Error("expected a miss for an unknown TWE id")
	}
}
