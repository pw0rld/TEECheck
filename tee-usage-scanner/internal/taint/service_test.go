package taint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type fakeEngine struct {
	calls   int
	results []codeql.Result
	fail    bool
}

func (*fakeEngine) Available() bool { return true }
func (f *fakeEngine) Analyze(_ context.Context, opts codeql.AnalyzeOptions) ([]codeql.Result, error) {
	f.calls++
	if opts.MaxPaths != 10 {
		return nil, errors.New("analysis path limit must be independent of display")
	}
	if f.fail {
		return nil, errors.New("temporary CodeQL failure")
	}
	return f.results, nil
}

type fakeDB struct{ calls int }

func (d *fakeDB) Ensure(_ context.Context, _ codedb.Scope) (string, error) {
	d.calls++
	return "existing-database", nil
}
func (*fakeDB) Path(codedb.Scope) string  { return "existing-database" }
func (*fakeDB) State(codedb.Scope) string { return codedb.StateReady }

func serviceFixture(t *testing.T) (*Service, Prepared, *fakeEngine, *fakeDB) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.c"), []byte("int entry(int value) { return value; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	manifest := artifacts.Manifest{RunID: "trace-test", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), manifest); err != nil {
		t.Fatal(err)
	}
	facts := artifacts.RepoFacts{RunID: manifest.RunID, Scope: scope, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable}, Symbols: []artifacts.Symbol{{SymbolID: "cpp:entry.c:1:entry(int)", Name: "entry", File: "entry.c", StartLine: 1, Signature: "(int)"}}}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), facts); err != nil {
		t.Fatal(err)
	}
	engine := &fakeEngine{results: []codeql.Result{{Paths: [][]codeql.PathStep{{{Path: "entry.c", StartLine: 1, Function: "entry", Expression: "value"}, {Path: "entry.c", StartLine: 1, Function: "entry", Expression: "derived"}, {Path: "entry.c", StartLine: 1, Function: "entry", Expression: "consume(value)"}}}}}}
	db := &fakeDB{}
	service := NewService(engine, db)
	p, err := service.Prepare(run, root, "fixture", "revision", Request{Parameters: Parameters{SourceFunc: "entry", SourceParamIndex: 0, SinkFunc: "consume"}, MaxPaths: 1, MaxHops: 1})
	if err != nil {
		t.Fatal(err)
	}
	return service, p, engine, db
}

func TestServiceCachesImmutableFullWitnessesIndependentlyOfDisplay(t *testing.T) {
	s, p, eng, db := serviceFixture(t)
	fact, path, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Status != "success" || len(fact.Paths) != 1 || len(fact.Paths[0]) != 3 || fact.Scope == nil || artifacts.ValidateToolFactContent(fact) != nil {
		t.Fatalf("invalid full fact: %+v", fact)
	}
	var rendered summary
	if err := json.Unmarshal([]byte(RenderSummary(fact, path, 1, 1)), &rendered); err != nil {
		t.Fatal(err)
	}
	if !rendered.Truncated || len(rendered.Paths) != 1 || len(rendered.Paths[0].Hops) != 1 {
		t.Fatalf("display bound ignored: %+v", rendered)
	}
	changed := p.Request
	changed.MaxPaths = 10
	changed.MaxHops = 20
	p2, err := s.Prepare(p.RunDir, p.RepoRoot, p.Repository, p.Commit, changed)
	if err != nil {
		t.Fatal(err)
	}
	if p.Key != p2.Key {
		t.Fatal("display preferences changed query identity")
	}
	if _, got, ok := s.Cached(p2); !ok || got != path {
		t.Fatal("same query did not hit cache")
	}
	if _, _, err := s.Run(context.Background(), p2); err != nil {
		t.Fatal(err)
	}
	if eng.calls != 1 || db.calls != 1 {
		t.Fatalf("cache repeated engine/db call: %d/%d", eng.calls, db.calls)
	}
	if err := os.WriteFile(filepath.Join(p.RepoRoot, "entry.c"), []byte("int entry(int value) { return value + 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p3, err := s.Prepare(p.RunDir, p.RepoRoot, p.Repository, p.Commit, p.Request)
	if err != nil {
		t.Fatal(err)
	}
	if p3.Key == p.Key {
		t.Fatal("source edit reused old source identity")
	}
	if _, _, ok := s.Cached(p3); ok {
		t.Fatal("source edit reused stale cache")
	}
}

func TestServiceFailureDoesNotPoisonSuccessfulRetry(t *testing.T) {
	s, p, eng, _ := serviceFixture(t)
	eng.fail = true
	failed, failedPath, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != "unresolved" {
		t.Fatalf("failure status %s", failed.Status)
	}
	before, err := os.ReadFile(failedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Cached(p); ok {
		t.Fatal("failure cached as successful evidence")
	}
	eng.fail = false
	good, goodPath, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if good.Status != "success" || goodPath == failedPath || eng.calls != 2 {
		t.Fatalf("failed retry: status=%s paths=%s/%s calls=%d", good.Status, failedPath, goodPath, eng.calls)
	}
	after, _ := os.ReadFile(failedPath)
	if string(before) != string(after) {
		t.Fatal("prior execution evidence overwritten")
	}
}

func TestServiceRejectsAlteredCachedEvidence(t *testing.T) {
	s, p, eng, _ := serviceFixture(t)
	_, path, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"modified":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Cached(p); ok {
		t.Fatal("tampered artifact accepted")
	}
	if _, _, err := s.Run(context.Background(), p); err == nil {
		t.Fatal("immutable artifact was replaced")
	}
	if eng.calls != 1 {
		t.Fatal("corrupt cached evidence should fail before re-executing the query")
	}
	body, _ := os.ReadFile(path)
	if string(body) != `{"modified":true}` {
		t.Fatal("existing evidence overwritten")
	}
}

func TestServiceRetainsMalformedAndMissingPathCoverage(t *testing.T) {
	s, p, eng, _ := serviceFixture(t)
	eng.results = append(eng.results, codeql.Result{Message: "missing path"}, codeql.Result{Paths: [][]codeql.PathStep{{{Path: "../outside.c", StartLine: 1}}}})
	fact, _, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	var meta Result
	if err := json.Unmarshal(fact.Result, &meta); err != nil {
		t.Fatal(err)
	}
	if len(fact.Paths) != 1 || len(meta.MalformedPaths) != 1 || meta.ResultsWithoutPaths != 1 {
		t.Fatalf("lost incomplete path records: %+v / %+v", meta, fact.Paths)
	}
	if !strings.Contains(strings.Join(fact.CoverageGaps, " "), "no path witnesses") {
		t.Fatal("missing path result was silently ignored")
	}
}

func TestCanonicalPathRejectsExternalOrParentLocations(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"../outside.c", "a/../../outside.c", "https://example.test/source.c", "/outside-root/source.c", "file://otherhost/source.c", "a\\b.c"} {
		if _, ok := canonicalPath([]codeql.PathStep{{Path: path, StartLine: 1}}, root); ok {
			t.Errorf("accepted out-of-scope location %q", path)
		}
	}
	path, ok := canonicalPath([]codeql.PathStep{{Path: "file://" + filepath.Join(root, "source.c"), StartLine: 1}}, root)
	if !ok || path[0].Location.Path != "source.c" {
		t.Fatalf("local file URI not normalized: %+v %v", path, ok)
	}
}

func TestZeroPathsDoesNotClaimSafety(t *testing.T) {
	s, p, eng, _ := serviceFixture(t)
	eng.results = nil
	fact, path, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Status != "success" || len(fact.Paths) != 0 || !strings.Contains(RenderSummary(fact, path, 5, 12), ZeroPathNotice) {
		t.Fatalf("zero paths overclaimed: %+v", fact)
	}
	if _, _, ok := s.Cached(p); !ok {
		t.Fatal("successful zero result should be cacheable without proving safety")
	}
}

func TestSummaryBoundsWholePathsAndClustering(t *testing.T) {
	fact := artifacts.ToolFact{FactID: "trace", Operation: Operation, Status: "success"}
	for i := 0; i < 40; i++ {
		path := []artifacts.ToolPathStep{}
		for j := 0; j < 30; j++ {
			path = append(path, artifacts.ToolPathStep{Location: artifacts.ToolLocation{Path: strings.Repeat("long-path/", 500) + "entry.c", StartLine: j + 1, Symbol: "entry"}, Message: strings.Repeat("expression ", 100)})
		}
		fact.Paths = append(fact.Paths, path)
	}
	fact.Result, _ = json.Marshal(Result{TotalPaths: len(fact.Paths)})
	body := RenderSummary(fact, "fact.json", 10, 20)
	var view summary
	if len(body) > observationlimits.MaxBytes || json.Unmarshal([]byte(body), &view) != nil || !view.Truncated || view.TotalPaths != 40 {
		t.Fatalf("invalid bounded summary: len=%d", len(body))
	}
	if len(fact.Paths) != 40 || len(fact.Paths[0]) != 30 {
		t.Fatal("render truncated persisted paths")
	}
}

func TestPrepareRejectsInvalidParametersBeforeExecution(t *testing.T) {
	s, p, eng, _ := serviceFixture(t)
	for _, mutate := range []func(*Request){func(r *Request) { r.SourceFunc = "entry\") or any()" }, func(r *Request) { r.SourcePath = "../entry.c" }, func(r *Request) { r.SourceParamIndex = -2 }, func(r *Request) { r.SinkKind = "all" }, func(r *Request) { r.BarrierFuncs = []string{"guard; injected"} }, func(r *Request) { r.MaxPaths = 11 }, func(r *Request) { r.MaxHops = 21 }, func(r *Request) { r.SinkFunc = "consume"; r.SinkKind = "array_index" }} {
		r := p.Request
		mutate(&r)
		if _, err := s.Prepare(p.RunDir, p.RepoRoot, p.Repository, p.Commit, r); err == nil {
			t.Fatalf("invalid parameters accepted: %+v", r)
		}
	}
	if _, err := s.Prepare(p.RunDir, p.RepoRoot, p.Repository, "different", p.Request); err == nil {
		t.Fatal("foreign commit accepted")
	}
	if eng.calls != 0 {
		t.Fatal("preparation invoked query engine")
	}
}
