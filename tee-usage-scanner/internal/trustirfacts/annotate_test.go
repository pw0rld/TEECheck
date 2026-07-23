package trustirfacts

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// stubAnnotateLLM is a canned test double for llm.Client, following the
// pattern internal/verifier/run_test.go's stubLLM and internal/expert's
// tests use — this package's tests must never call a real model (testing
// constraint: no live LLM calls).
type stubAnnotateLLM struct {
	response    string
	err         error
	calls       int
	lastRequest llm.GenerateRequest
}

func (s *stubAnnotateLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.calls++
	s.lastRequest = req
	if s.err != nil {
		return llm.GenerateResponse{}, s.err
	}
	return llm.GenerateResponse{Text: s.response}, nil
}

var _ llm.Client = (*stubAnnotateLLM)(nil)

func writeRollbackFixtureTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "core", "crypto", "signed_hdr.c"), rollbackFixtureC)
	return dir
}

func TestAnnotateFactTable_HappyPath(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)
	stub := &stubAnnotateLLM{response: `{
		"claim_producers": [{"function": "shdr_load_pub_key", "role": "security_version"}],
		"rollback_fields": ["version"],
		"produced_structs": ["shdr_pub_key"],
		"rollback_authorities": [{"function": "check_update_version", "kind": "state_restore_acceptance"}]
	}`}

	table, report, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err != nil {
		t.Fatalf("AnnotateFactTable: %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("expected exactly one LLM call, got %d", stub.calls)
	}
	if len(report.Unresolved) != 0 {
		t.Errorf("expected no unresolved annotations, got %+v", report.Unresolved)
	}
	if table.Empty() {
		t.Fatal("expected a non-empty resolved fact table")
	}
	if len(table.ClaimProducers) != 1 || table.ClaimProducers[0].Function != "shdr_load_pub_key" {
		t.Errorf("ClaimProducers = %+v", table.ClaimProducers)
	}
	if len(report.Candidates.Functions) == 0 {
		t.Error("expected AnnotationReport.Candidates to carry the enumerated candidates")
	}
}

// TestAnnotateFactTable_DropsInventedNames is the resolver-integration
// counterpart of §23.3's "unresolved annotations are dropped and recorded,
// never silently kept": one real, resolvable annotation and one invented,
// unresolvable one in the SAME response — only the real one may survive
// into the table.
func TestAnnotateFactTable_DropsInventedNames(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)
	stub := &stubAnnotateLLM{response: `{
		"claim_producers": [
			{"function": "shdr_load_pub_key", "role": "security_version"},
			{"function": "a_function_that_does_not_exist", "role": "security_version"}
		]
	}`}

	table, report, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err != nil {
		t.Fatalf("AnnotateFactTable: %v", err)
	}
	if len(table.ClaimProducers) != 1 || table.ClaimProducers[0].Function != "shdr_load_pub_key" {
		t.Errorf("ClaimProducers = %+v, want only the resolvable one", table.ClaimProducers)
	}
	if len(report.Unresolved) != 1 || report.Unresolved[0].Value != "a_function_that_does_not_exist" {
		t.Errorf("Unresolved = %+v, want the invented name recorded", report.Unresolved)
	}
}

func TestAnnotateFactTable_NoLLMClient(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)

	_, _, err := AnnotateFactTable(context.Background(), nil, registry, dir)
	if err == nil {
		t.Fatal("expected an error when no LLM client is configured")
	}
}

// TestAnnotateFactTable_EmptyTreeNeverCallsLLM proves an empty/unusable
// source tree fails fast on the deterministic Enumerate step and never
// reaches the LLM at all — important for cost control (§11) and for
// keeping this an honest "no evidence" outcome rather than asking a model
// to hallucinate over nothing.
func TestAnnotateFactTable_EmptyTreeNeverCallsLLM(t *testing.T) {
	dir := t.TempDir()
	registry := realRegistry(t)
	stub := &stubAnnotateLLM{response: `{}`}

	_, report, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err == nil {
		t.Fatal("expected an error for a source tree with no enumerable candidates")
	}
	if stub.calls != 0 {
		t.Errorf("expected zero LLM calls for an empty tree, got %d", stub.calls)
	}
	if len(report.Candidates.Functions) != 0 {
		t.Errorf("expected empty candidates in the report, got %+v", report.Candidates)
	}
}

func TestAnnotateFactTable_LLMErrorIsWrapped(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)
	boom := errors.New("llm boom")
	stub := &stubAnnotateLLM{err: boom}

	_, _, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("expected the underlying LLM error to be wrapped, got %v", err)
	}
}

func TestAnnotateFactTable_MalformedResponseIsAnError(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)
	stub := &stubAnnotateLLM{response: "not json at all, sorry"}

	_, report, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err == nil {
		t.Fatal("expected an error for a response that does not parse as the annotation schema")
	}
	if report.RawResponse == "" {
		t.Error("expected the raw response to be preserved in the report even on a parse failure")
	}
}

func TestAnnotateFactTable_EmptyModelResponseYieldsEmptyTableNoError(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	registry := realRegistry(t)
	stub := &stubAnnotateLLM{response: `{"claim_producers": [], "rollback_fields": [], "produced_structs": [], "rollback_authorities": []}`}

	table, report, err := AnnotateFactTable(context.Background(), stub, registry, dir)
	if err != nil {
		t.Fatalf("AnnotateFactTable: %v", err)
	}
	if !table.Empty() {
		t.Errorf("expected an Empty table, got %+v", table)
	}
	if len(report.Unresolved) != 0 {
		t.Errorf("expected no unresolved entries for an empty response, got %+v", report.Unresolved)
	}
}

func TestBuildAnnotationPrompt_ListsRegistryValuesVerbatimAndNoLineNumbers(t *testing.T) {
	registry := realRegistry(t)
	cand := Candidates{
		Functions: []FunctionCandidate{{Name: "shdr_load_pub_key", Files: []string{"a.c"}}},
		Fields:    []string{"version"},
		Structs:   []string{"shdr_pub_key"},
	}
	prompt := buildAnnotationPrompt(cand, registry)

	for _, want := range []string{"shdr_load_pub_key", "version", "shdr_pub_key", "security_version", "state_restore_acceptance"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	// §23.4.1: candidates are named, never line-anchored — the prompt must
	// not encourage the model to reason about (and this package must never
	// key resolution on) a specific line number.
	if strings.Contains(prompt, "line ") || strings.Contains(prompt, ":line") {
		t.Error("prompt must not reference line numbers")
	}
}

func TestBuildAnnotationPrompt_TruncatesLargeFunctionLists(t *testing.T) {
	registry := realRegistry(t)
	var funcs []FunctionCandidate
	for i := 0; i < maxPromptFunctionNames+50; i++ {
		funcs = append(funcs, FunctionCandidate{Name: "fn_" + strconv.Itoa(i)})
	}
	cand := Candidates{Functions: funcs}
	prompt := buildAnnotationPrompt(cand, registry)

	if !strings.Contains(prompt, "truncated") {
		t.Error("expected the prompt to disclose truncation for an oversized candidate list")
	}
}
