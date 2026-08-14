package twecontext

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// TestPlaybookValidatesAgainstSchema is PR-01's per-schema round-trip test
// for schemas/twe-playbook.v1.json (schema.TWEPlaybookV1). Playbook.Validate
// already enforces most of this at load time; this test proves the JSON a
// Playbook marshals to is also accepted by the canonical schema itself, and
// that the schema rejects what Playbook.Validate would also reject.
func TestPlaybookValidatesAgainstSchema(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "test.yml", validPlaybook)
	catalog, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	playbooks := catalog.All()
	if len(playbooks) != 1 {
		t.Fatalf("want 1 playbook, got %d", len(playbooks))
	}
	data, err := json.Marshal(playbooks[0])
	if err != nil {
		t.Fatalf("marshal playbook: %v", err)
	}
	if err := schema.Validate(schema.TWEPlaybookV1, data); err != nil {
		t.Fatalf("valid Playbook rejected: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	// Missing required field.
	missingScenario := cloneMap(doc)
	delete(missingScenario, "scenario")
	if err := schema.Validate(schema.TWEPlaybookV1, mustMarshal(t, missingScenario)); err == nil {
		t.Fatal("expected missing scenario to be rejected")
	}

	// family enum: Flow|Guard|Binding|State|Config|Design|Leakage.
	badFamily := cloneMap(doc)
	badFamily["family"] = "Rollback"
	if err := schema.Validate(schema.TWEPlaybookV1, mustMarshal(t, badFamily)); err == nil {
		t.Fatal("expected an out-of-enum family to be rejected")
	}

	// investigation_steps has minItems:1 — an empty-but-present array must
	// fail even though it is structurally a valid JSON array.
	emptySteps := cloneMap(doc)
	emptySteps["investigation_steps"] = []any{}
	if err := schema.Validate(schema.TWEPlaybookV1, mustMarshal(t, emptySteps)); err == nil {
		t.Fatal("expected empty investigation_steps to be rejected (minItems: 1)")
	}
}

func TestShippedRollbackPlaybookValidatesAgainstSchema(t *testing.T) {
	dir := filepath.Join("..", "..", "knowledge", "twe", "exemplars")
	catalog, err := Load(dir)
	if err != nil {
		t.Fatalf("load shipped playbooks: %v", err)
	}
	for _, playbook := range catalog.All() {
		data, err := json.Marshal(playbook)
		if err != nil {
			t.Fatalf("marshal %s: %v", playbook.ID, err)
		}
		if err := schema.Validate(schema.TWEPlaybookV1, data); err != nil {
			t.Errorf("shipped playbook %s fails schema validation: %v", playbook.ID, err)
		}
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
