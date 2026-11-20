package trustirfacts

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestTrustIRIsolatedFactTablesAcrossAdjacentCommits(t *testing.T) {
	tableA := FactTable{RollbackFields: []string{"version"}}
	tableB := FactTable{RollbackFields: []string{"epoch"}}
	a := Request{RunDir: t.TempDir(), Repository: "https://example.invalid/repo", Commit: "aaa", Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t), FactTable: NewFactTableInput("https://example.invalid/repo", "aaa", tableA, "llm_annotated")}
	b := a
	b.RunDir = t.TempDir()
	b.Commit = "bbb"
	b.FactTable = NewFactTableInput(b.Repository, b.Commit, tableB, "llm_annotated")
	fa, err := Run(context.Background(), nil, nil, a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := Run(context.Background(), nil, nil, b)
	if err != nil {
		t.Fatal(err)
	}
	if fa.FactTableSHA256 == fb.FactTableSHA256 {
		t.Fatal("adjacent versions shared a mutable table")
	}
	wrong := a
	wrong.Commit = "bbb"
	if _, err := Run(context.Background(), nil, nil, wrong); err == nil {
		t.Fatal("table from another commit accepted")
	}
	plain := a
	plain.FactTable = nil
	if f, err := Run(context.Background(), nil, nil, plain); err != nil || f.Status != StatusUnsupported {
		t.Fatal("explicit table leaked into an unrelated request")
	}
}

func TestQueryRevisionGetsSeparateExecutionIdentity(t *testing.T) {
	repo, commit := localRepo(t)
	pack := filepath.Join(t.TempDir(), "pack")
	if err := copyTree(checkedInQueryPackDir(t), pack); err != nil {
		t.Fatal(err)
	}
	req := Request{RunDir: t.TempDir(), Repository: repo, Commit: commit, Operation: OperationRollbackVersionPropagation, QueryPackDir: pack, FactTable: NewFactTableInput(repo, commit, FactTable{RollbackFields: []string{"version"}}, "llm_annotated")}
	eng := &fakeEngine{available: true}
	a, pa, err := RunAndPersist(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pack, "state", "RollbackVersionNotPropagated.ql")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("\n// next query revision\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	b, pb, err := RunAndPersist(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.ArgumentsSHA256 == b.ArgumentsSHA256 || pa == pb {
		t.Fatal("query revision silently reused earlier evidence identity")
	}
}

func TestPersistConcurrentIdenticalPublication(t *testing.T) {
	runDir := t.TempDir()
	fact := newFact(Request{Repository: "test", Commit: "abc", Operation: OperationRollbackVersionPropagation})
	fact.Status = StatusUnsupported
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := Persist(runDir, fact); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var got artifacts.ToolFact
	if err := runfs.ReadJSON(runfs.TrustIRToolFactPath(runDir, fact.FactID), &got); err != nil {
		t.Fatal(err)
	}
	if got.FactID != fact.FactID {
		t.Fatal("published file was incomplete")
	}
}

func TestPersistCoexistsAcrossFactTableDigests(t *testing.T) {
	runDir := t.TempDir()
	req := Request{RunDir: runDir, Repository: "https://example.invalid/repo", Commit: "aaa", Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t)}
	req.FactTable = NewFactTableInput(req.Repository, req.Commit, FactTable{RollbackFields: []string{"version"}}, "llm_annotated")
	a, pa, err := RunAndPersist(context.Background(), nil, nil, req)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(pa)
	if err != nil {
		t.Fatal(err)
	}
	req.FactTable = NewFactTableInput(req.Repository, req.Commit, FactTable{RollbackFields: []string{"epoch"}}, "llm_annotated")
	b, pb, err := RunAndPersist(context.Background(), nil, nil, req)
	if err != nil {
		t.Fatal(err)
	}
	if a.FactID == b.FactID || pa == pb {
		t.Fatal("different tables reused the same evidence identity")
	}
	after, err := os.ReadFile(pa)
	if err != nil || string(before) != string(after) {
		t.Fatal("new table overwrote earlier evidence")
	}
}
