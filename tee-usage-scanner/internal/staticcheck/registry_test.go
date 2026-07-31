package staticcheck_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type fakeAdapter struct {
	name      string
	available bool
	findings  []staticcheck.CheckFinding
}

func (f *fakeAdapter) Name() string    { return f.name }
func (f *fakeAdapter) Available() bool { return f.available }
func (f *fakeAdapter) Run(_ context.Context, _ staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	return f.findings, nil
}

func TestRegistryRunAll(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{
		name: "tool-a", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-a", Path: "a.rs", Message: "hit-a"}},
	})
	reg.Register(&fakeAdapter{name: "tool-b", available: false})
	reg.Register(&fakeAdapter{
		name: "tool-c", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-c", Path: "c.rs", Message: "hit-c"}},
	})

	results, err := reg.RunAll(context.Background(), staticcheck.CheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(results))
	}
	if results[0].ToolName != "tool-a" || results[1].ToolName != "tool-c" {
		t.Fatalf("unexpected findings: %+v", results)
	}
}

func TestRegistryRunByName(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{
		name: "tool-a", available: true,
		findings: []staticcheck.CheckFinding{{ToolName: "tool-a", Path: "a.rs", Message: "hit"}},
	})

	results, err := reg.RunByName(context.Background(), "tool-a", staticcheck.CheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	_, err = reg.RunByName(context.Background(), "missing", staticcheck.CheckRequest{})
	if err == nil {
		t.Fatal("expected error for missing adapter")
	}
}

func TestRegistryAvailable(t *testing.T) {
	reg := staticcheck.NewRegistry()
	reg.Register(&fakeAdapter{name: "yes", available: true})
	reg.Register(&fakeAdapter{name: "no", available: false})

	avail := reg.Available()
	if len(avail) != 1 || avail[0] != "yes" {
		t.Fatalf("expected [yes], got %v", avail)
	}
}
