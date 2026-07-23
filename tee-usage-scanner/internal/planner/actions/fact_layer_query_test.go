package actions_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// fakeFactEngine is this package's own test double for
// trustirfacts.Engine — never a real codeql binary, never a real database
// build (disk/CPU/network are constrained in this environment; see
// internal/trustirfacts's fakeEngine, which this mirrors, and its doc
// comment for why the interface exists). Defined locally rather than by
// editing internal/trustirfacts, which this package must not modify.
type fakeFactEngine struct {
	available bool
}

func (f *fakeFactEngine) Available() bool { return f.available }

func (f *fakeFactEngine) CreateDatabase(_ context.Context, _ codeql.CreateDBOptions) error {
	return nil
}

func (f *fakeFactEngine) Analyze(_ context.Context, _ codeql.AnalyzeOptions) ([]codeql.Result, error) {
	return nil, nil
}

func factLayerArgs(t *testing.T, operation string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"operation": operation})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFactLayerQuery_Name(t *testing.T) {
	h := &actions.FactLayerQueryHandler{}
	if h.Name() != "fact_layer_query" {
		t.Fatalf("Name() = %q, want fact_layer_query", h.Name())
	}
}

func TestFactLayerQuery_InvalidArgs(t *testing.T) {
	h := &actions.FactLayerQueryHandler{Engine: &fakeFactEngine{available: true}}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "fact_layer_query",
		Args: json.RawMessage("not json"),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}

func TestFactLayerQuery_MissingOperation(t *testing.T) {
	h := &actions.FactLayerQueryHandler{Engine: &fakeFactEngine{available: true}}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "fact_layer_query",
		Args: factLayerArgs(t, ""),
	})
	if result.OK {
		t.Fatal("expected failure when operation is empty")
	}
}

func TestFactLayerQuery_NoEngineConfigured(t *testing.T) {
	h := &actions.FactLayerQueryHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, "cpp.state.rollback_version_propagation"),
		RunDir:     t.TempDir(),
		Repository: "https://github.com/OP-TEE/optee_os",
		Commit:     "abc123",
	})
	if result.OK {
		t.Fatal("expected failure when Engine is nil (e.g. --facts off)")
	}
	if !strings.Contains(result.Error, "engine") {
		t.Errorf("Error = %q, want it to explain the missing engine", result.Error)
	}
}

func TestFactLayerQuery_MissingRunContext(t *testing.T) {
	h := &actions.FactLayerQueryHandler{Engine: &fakeFactEngine{available: true}}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "fact_layer_query",
		Args: factLayerArgs(t, "cpp.state.rollback_version_propagation"),
		// RunDir/Repository/Commit deliberately left unset.
	})
	if result.OK {
		t.Fatal("expected failure when run_dir/repository/commit are unset")
	}
}

// TestFactLayerQuery_UnsupportedRepositoryNeverTouchesEngine proves the
// action's happy (non-error) path never fakes evidence: an unregistered
// repository is a legitimate "unsupported" ToolFact status, not a Go error,
// and it must be reachable without the fake engine's CreateDatabase/Analyze
// ever being called — the exact "no real DB build" contract this package's
// tests run under (§ the task's testing constraint).
func TestFactLayerQuery_UnsupportedRepositoryNeverTouchesEngine(t *testing.T) {
	eng := &fakeFactEngine{available: true}
	h := &actions.FactLayerQueryHandler{Engine: eng, QueryPackDir: "does-not-need-to-exist-for-this-path"}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, "cpp.state.rollback_version_propagation"),
		RunDir:     t.TempDir(),
		Repository: "https://example.com/unregistered-repo",
		Commit:     "deadbeef",
	})
	if !result.OK {
		t.Fatalf("expected OK=true (an unsupported ToolFact status is a legitimate observation, not an action failure): %s", result.Error)
	}
	if !strings.Contains(result.Output, `"status": "unsupported"`) {
		t.Errorf("Output = %s, want status=unsupported", result.Output)
	}
	if !strings.Contains(result.Output, "tool_fact_ref") {
		t.Errorf("Output = %s, want a tool_fact_ref (artifact reference, not a giant blob)", result.Output)
	}
}
