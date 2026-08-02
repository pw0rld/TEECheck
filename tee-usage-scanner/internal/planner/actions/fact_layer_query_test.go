package actions_test

import (
	"context"
	"encoding/json"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
	"os"
	"path/filepath"
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
	// results is what Analyze reports back. Zero value (nil) keeps the
	// existing tests' behaviour: a query that ran and matched nothing.
	results []codeql.Result
}

func (f *fakeFactEngine) Available() bool { return f.available }

// CreateDatabase makes the output directory a real codeql would have made.
// Returning nil without it left the fact layer unable to write its
// db-built marker, so every path through this fake ended at status
// "unresolved" — which quietly satisfies any assertion phrased as "the
// observation does NOT contain X".
func (f *fakeFactEngine) CreateDatabase(_ context.Context, opts codeql.CreateDBOptions) error {
	return os.MkdirAll(opts.DBPath, 0o755)
}

func (f *fakeFactEngine) Analyze(_ context.Context, _ codeql.AnalyzeOptions) ([]codeql.Result, error) {
	return f.results, nil
}

// realQueryPackDir returns the repository's own CodeQL pack. The fact layer
// copies it and then reads the operation's .ql back, so a t.TempDir() here
// makes every request fail at "materialize query pack" with status "error" —
// which never reaches the observation code these tests are about.
func realQueryPackDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "codeql", "trustir", "cpp")
	if _, err := os.Stat(filepath.Join(dir, "state", "RollbackVersionNotPropagated.ql")); err != nil {
		t.Skipf("query pack not present at %s: %v", dir, err)
	}
	return dir
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

// An operation outside the closed vocabulary must fail at the edge, naming
// the legal values. Nothing checked before: an invented operation reached
// trustirfacts.Run, which persisted an "unsupported" ToolFact for a query
// that never ran, and whose error text blamed the repository rather than
// the operation. Observed for real on 2026-07-27 with
// "cpp.flow.bounds_check_consistency".
func TestFactLayerQuery_UnknownOperationIsRejectedWithTheVocabulary(t *testing.T) {
	h := &actions.FactLayerQueryHandler{Engine: nil, QueryPackDir: "irrelevant"}
	res := h.Run(context.Background(), actions.ActionRequest{
		Args: []byte(`{"operation":"cpp.flow.bounds_check_consistency"}`),
	})
	if res.OK {
		t.Fatal("an operation outside the vocabulary must not be accepted")
	}
	if !strings.Contains(res.Error, "unknown operation") {
		t.Errorf("error must say the operation is unknown, got: %q", res.Error)
	}
	for _, op := range trustirfacts.SupportedOperationStrings() {
		if !strings.Contains(res.Error, op) {
			t.Errorf("error must name the legal value %q so the model can correct itself; got: %q", op, res.Error)
		}
	}
}

// TestFactLayerQuery_ObservationCarriesFindingsAndRelatedSites drives the
// whole action — real git, fake CodeQL — and asserts on what the Planner
// actually sees back.
//
// This is CVE-2026-44362's failure, reduced. The fact layer resolved the
// rollback authority to a site in ANOTHER FILE (core/kernel/ree_fs_ta.c) and
// persisted it, but the observation projected only the primary location.
// Not knowing a caller had already been found, the Planner ran reverse_trace
// over a single-file fixture, got "(no callers found)", and the Challenger
// turned that into "the whole path is dead code". The authority location was
// on disk the entire time. See docs/bugs/BUG-002 §3.4.
func TestFactLayerQuery_ObservationCarriesFindingsAndRelatedSites(t *testing.T) {
	repo, commit := gitInit(t)
	trustirfacts.SetFactTable(repo, trustirfacts.FactTable{RollbackFields: []string{"version"}})
	t.Cleanup(trustirfacts.ResetFactTables)

	handler := &actions.FactLayerQueryHandler{
		QueryPackDir: realQueryPackDir(t),
		Engine: &fakeFactEngine{available: true, results: []codeql.Result{{
			RuleID:    "trustir/state/rollback-version-propagation",
			Message:   "TWE-STATE-001: producer shdr_load_pub_key never propagates rollback field 'version'; authority check_update_version therefore checks a default version.",
			Path:      "core/crypto/signed_hdr.c",
			StartLine: 262,
			Related: []codeql.RelatedLocation{
				{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
				{Path: "core/kernel/ree_fs_ta.c", StartLine: 314, Symbol: "check_update_version"},
			},
		}}},
	}

	res := handler.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, string(trustirfacts.OperationRollbackVersionPropagation)),
		RunDir:     t.TempDir(),
		Repository: repo,
		Commit:     commit,
	})
	if !res.OK {
		t.Fatalf("handler failed: %+v", res)
	}

	// The message is the query's conclusion — without it the observation
	// says "something was flagged here" and nothing about what.
	if !strings.Contains(res.Output, "never propagates rollback field") {
		t.Errorf("observation must carry the finding message; got:\n%s", res.Output)
	}
	// The authority site lives in a different file from the primary
	// location. This is the field whose absence cost the run the finding.
	if !strings.Contains(res.Output, "core/kernel/ree_fs_ta.c") {
		t.Errorf("observation must carry related sites in other files; got:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "check_update_version") {
		t.Errorf("a related site's symbol is what makes it actionable; got:\n%s", res.Output)
	}
	// Still an artifact reference, not the raw payload (§11.2/§24).
	if !strings.Contains(res.Output, "tool_fact_ref") {
		t.Errorf("observation must still reference the persisted ToolFact; got:\n%s", res.Output)
	}
}

// A run that matched nothing must not grow a findings key — "we looked and
// found nothing" and "we found something" have to stay distinguishable.
func TestFactLayerQuery_NoMatchesCarriesNoFindings(t *testing.T) {
	repo, commit := gitInit(t)
	trustirfacts.SetFactTable(repo, trustirfacts.FactTable{RollbackFields: []string{"version"}})
	t.Cleanup(trustirfacts.ResetFactTables)

	handler := &actions.FactLayerQueryHandler{
		QueryPackDir: realQueryPackDir(t),
		Engine:       &fakeFactEngine{available: true},
	}
	res := handler.Run(context.Background(), actions.ActionRequest{
		Name:       "fact_layer_query",
		Args:       factLayerArgs(t, string(trustirfacts.OperationRollbackVersionPropagation)),
		RunDir:     t.TempDir(),
		Repository: repo,
		Commit:     commit,
	})
	if !res.OK {
		t.Fatalf("handler failed: %+v", res)
	}
	if strings.Contains(res.Output, `"findings"`) {
		t.Errorf("a zero-match success must not emit a findings key; got:\n%s", res.Output)
	}
}

// A known operation must get past the vocabulary check — the guard must not
// reject everything.
func TestFactLayerQuery_KnownOperationPassesTheVocabularyCheck(t *testing.T) {
	ops := trustirfacts.SupportedOperationStrings()
	if len(ops) == 0 {
		t.Skip("no executable operations in this build")
	}
	h := &actions.FactLayerQueryHandler{Engine: nil, QueryPackDir: "irrelevant"}
	res := h.Run(context.Background(), actions.ActionRequest{
		Args: []byte(`{"operation":"` + ops[0] + `"}`),
	})
	// It still fails — the engine is nil — but on the engine, not the vocabulary.
	if strings.Contains(res.Error, "unknown operation") {
		t.Fatalf("a legal operation was rejected as unknown: %q", res.Error)
	}
}
