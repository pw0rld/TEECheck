package staticcheck

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubAdapter struct {
	name      string
	available bool
	findings  []CheckFinding
	err       error
}

func (s stubAdapter) Name() string    { return s.name }
func (s stubAdapter) Available() bool { return s.available }
func (s stubAdapter) Run(context.Context, CheckRequest) ([]CheckFinding, error) {
	return s.findings, s.err
}

// One adapter that cannot run must not discard what the others found.
//
// RunAll returned on the first error, so scanner-001 — the only tool-backed
// bus agent — answered "adapter codeql: a prebuilt database is required" and
// dropped grep's hits with it. On 2026-08-01 both of the arbiter's queries to
// it failed that way, and the arbiter fell back to asking an agent with no
// tools at all, which invented a call graph.
func TestRunAll_OneFailingAdapterDoesNotDiscardTheRest(t *testing.T) {
	r := NewRegistry()
	r.Register(stubAdapter{name: "grep", available: true,
		findings: []CheckFinding{{Path: "a.c", StartLine: 1, Message: "hit"}}})
	r.Register(stubAdapter{name: "codeql", available: true, err: errors.New("a prebuilt database is required")})

	got, err := r.RunAll(context.Background(), CheckRequest{RepoRoot: "."})
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want the working adapter's hit kept", got)
	}
	if err == nil {
		t.Fatal("the failure must still be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), "codeql") {
		t.Errorf("the error must name the adapter that failed: %v", err)
	}
	if strings.Contains(err.Error(), "grep") {
		t.Errorf("the working adapter must not appear in the error: %v", err)
	}
}

// Every adapter failing is still an error, and still reports each one.
func TestRunAll_AllFailing(t *testing.T) {
	r := NewRegistry()
	r.Register(stubAdapter{name: "codeql", available: true, err: errors.New("no db")})
	r.Register(stubAdapter{name: "joern", available: true, err: errors.New("not installed")})
	_, err := r.RunAll(context.Background(), CheckRequest{})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"codeql", "joern"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %s: %v", want, err)
		}
	}
}
