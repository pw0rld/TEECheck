package taint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type prescanTestEngine struct {
	calls     int
	results   []codeql.Result
	err       error
	queryPath string
	deadline  bool
}

func (*prescanTestEngine) Available() bool                         { return true }
func (*prescanTestEngine) Version(context.Context) (string, error) { return "2.24.0", nil }
func (e *prescanTestEngine) Analyze(ctx context.Context, opts codeql.AnalyzeOptions) ([]codeql.Result, error) {
	e.calls++
	_, e.deadline = ctx.Deadline()
	if len(opts.Queries) != 1 || !filepath.IsAbs(opts.Queries[0]) || opts.Queries[0] != e.queryPath || opts.MaxPaths != 10 {
		return nil, errors.New("expected one static absolute query with bounded emitted witnesses")
	}
	return e.results, e.err
}

type prescanTestDB struct {
	ensureCalls int
	state       string
}

func (d *prescanTestDB) Ensure(context.Context, codedb.Scope) (string, error) {
	d.ensureCalls++
	return "", errors.New("prescan must never create/rebuild databases")
}
func (*prescanTestDB) Path(codedb.Scope) string    { return "/already-ready/private-db" }
func (d *prescanTestDB) State(codedb.Scope) string { return d.state }

func prescanTestFixture(t *testing.T) (PrescanRequest, *prescanTestEngine, *prescanTestDB) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	for _, path := range []string{"core/tee/tee_svc_cryp.c", "core/tee/entry_std.c", "lib/libtomcrypt/ciphers/cast5.c", "lib/mbedtls/aes.c"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(strings.Repeat("int observed;\n", 40)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	query := filepath.Join(t.TempDir(), "EntrySurfaceToSink.ql")
	if err := os.WriteFile(query, []byte("// fixed query fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	manifest := artifacts.Manifest{RunID: "prescan-run", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), manifest); err != nil {
		t.Fatal(err)
	}
	facts := &artifacts.RepoFacts{RunID: manifest.RunID, Scope: scope, EntrySurfaces: []artifacts.EntrySurface{{Name: "dispatch", Path: "core/tee/entry_std.c", StartLine: 1, EndLine: 10, Signals: []string{artifacts.EntrySignalGlobalFunctionPointerInitializer}}}}
	req := PrescanRequest{RunDir: run, RepoRoot: root, Repository: "fixture", Commit: "revision", QueryPath: query, Facts: facts}
	eng := &prescanTestEngine{queryPath: query}
	db := &prescanTestDB{state: codedb.StateReady}
	return req, eng, db
}

func prescanTestResult(sourceFile, sourceFunc, sinkFile, kind, sink string, line, nodes int) codeql.Result {
	path := make([]codeql.PathStep, 0, nodes)
	path = append(path, codeql.PathStep{Path: sourceFile, StartLine: 1, Function: sourceFunc, Expression: "source parameter"})
	for i := 1; i < nodes-1; i++ {
		path = append(path, codeql.PathStep{Path: sinkFile, StartLine: i + 1, Function: "consumer", Expression: "derived expression"})
	}
	path = append(path, codeql.PathStep{Path: sinkFile, StartLine: line, Function: "consumer", Expression: sink + "(value)"})
	return codeql.Result{Message: "teecheck_entry_taint source_signal=global_function_pointer_initializer;sink_kind=" + kind + ";sink_func=" + sink, Paths: [][]codeql.PathStep{path}}
}

func TestPrescanRunsOneStaticQueryAndKeepsCompleteWitnessArtifact(t *testing.T) {
	req, eng, db := prescanTestFixture(t)
	r := prescanTestResult("core/tee/entry_std.c", "dispatch", "core/tee/tee_svc_cryp.c", "memory_call", "memcpy", 30, 15)
	eng.results = []codeql.Result{r, r}
	out, err := RunPrescan(context.Background(), eng, db, req)
	if err != nil {
		t.Fatal(err)
	}
	if eng.calls != 1 || !eng.deadline || db.ensureCalls != 0 {
		t.Fatalf("analysis=%d deadline=%v Ensure=%d", eng.calls, eng.deadline, db.ensureCalls)
	}
	if out.Fact.Status != "success" || out.Fact.Operation != PrescanOperation || len(out.Fact.Paths) != 1 || len(out.Fact.Paths[0]) != 15 {
		t.Fatalf("full witnesses lost: %+v", out.Fact)
	}
	if !filepath.IsAbs(out.FactRef) || artifacts.ValidateToolFactContent(out.Fact) != nil || len(out.Summary) > PrescanSummaryMaxBytes {
		t.Fatal("invalid artifact identity or summary bound")
	}
	var meta PrescanResult
	if json.Unmarshal(out.Fact.Result, &meta) != nil || len(meta.Candidates) != 1 || meta.RawWitnessCount != 2 {
		t.Fatalf("invalid aggregate: %+v", meta)
	}
	if len(out.Fact.Findings) != 0 {
		t.Fatal("prescan directly promoted a finding")
	}
	if !strings.Contains(out.Summary, "not verdicts") || !strings.Contains(out.Summary, out.FactRef) {
		t.Fatal("summary lost neutral provenance")
	}
	if _, err = RunPrescan(context.Background(), eng, db, req); err != nil || eng.calls != 1 {
		t.Fatalf("run-local recovery repeated engine: %v / %d", err, eng.calls)
	}
	var changed artifacts.ToolFact
	if err = runfs.ReadJSON(out.FactRef, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Paths[0][0].Message = "tampered"
	if err = runfs.WriteJSON(out.FactRef, changed); err != nil {
		t.Fatal(err)
	}
	if _, err = RunPrescan(context.Background(), eng, db, req); err == nil || eng.calls != 1 {
		t.Fatal("tampered artifact was overwritten or reused")
	}
}

func TestPrescanRankingDeduplicatesAndLimitsSourceSinkFilePairs(t *testing.T) {
	source := artifacts.ToolLocation{Path: "core/tee/entry_std.c", StartLine: 1, Symbol: "dispatch"}
	sink := artifacts.ToolLocation{Path: "core/tee/tee_svc_cryp.c", StartLine: 10}
	base := PrescanCandidate{SourceFunc: "dispatch", SinkFunc: "memcpy", Source: source, Sink: sink, Hops: 7, Score: 50}
	short := base
	short.Hops = 3
	short.PathIndex = 1
	b := base
	b.Sink.StartLine = 11
	b.PathIndex = 2
	c := base
	c.Sink.StartLine = 12
	c.PathIndex = 3
	got := RankPrescanCandidates([]PrescanCandidate{base, short, b, c})
	if len(got) != 2 || got[0].PathIndex != 1 || got[0].Hops != 3 {
		t.Fatalf("dedupe/diversity failed: %+v", got)
	}
}

func TestPrescanCryptoArrayNoiseRanksAfterServiceBoundary(t *testing.T) {
	req, eng, db := prescanTestFixture(t)
	eng.results = []codeql.Result{
		prescanTestResult("lib/libtomcrypt/ciphers/cast5.c", "cast5", "lib/libtomcrypt/ciphers/cast5.c", "array_index", "", 12, 2),
		prescanTestResult("lib/mbedtls/aes.c", "aes", "lib/mbedtls/aes.c", "array_index", "", 11, 2),
		prescanTestResult("core/tee/entry_std.c", "dispatch", "core/tee/tee_svc_cryp.c", "memory_call", "memcpy", 20, 4),
	}
	out, err := RunPrescan(context.Background(), eng, db, req)
	if err != nil {
		t.Fatal(err)
	}
	var meta PrescanResult
	_ = json.Unmarshal(out.Fact.Result, &meta)
	if len(meta.Candidates) != 3 || meta.Candidates[0].Sink.Path != "core/tee/tee_svc_cryp.c" {
		t.Fatalf("crypto noise precedes service path: %+v", meta.Candidates)
	}
	if len(out.Fact.Paths) != 3 {
		t.Fatal("downweighting deleted emitted witnesses")
	}
}

func TestPrescanPairDiversitySelectsShortestBeforeNavigationScore(t *testing.T) {
	base := PrescanCandidate{SourceFunc: "entry", Source: artifacts.ToolLocation{Path: "entry.c", StartLine: 1}, Sink: artifacts.ToolLocation{Path: "service.c", StartLine: 10}, SinkFunc: "array_index", Hops: 2, PathIndex: 0}
	longer := base
	longer.Sink.StartLine, longer.Hops, longer.Score, longer.PathIndex = 11, 10, 20, 1
	longest := longer
	longest.Sink.StartLine, longest.Hops, longest.PathIndex = 12, 11, 2
	got := RankPrescanCandidates([]PrescanCandidate{base, longer, longest})
	if len(got) != 2 {
		t.Fatalf("pair cap=%d", len(got))
	}
	seen := map[int]bool{}
	for _, c := range got {
		seen[c.PathIndex] = true
	}
	if !seen[0] || !seen[1] || seen[2] {
		t.Fatalf("navigation score displaced shortest witnesses: %+v", got)
	}
}

func TestPrescanSummaryIsBoundedAndEmptyResultIsNotSafety(t *testing.T) {
	req, eng, db := prescanTestFixture(t)
	for i := 0; i < 25; i++ {
		r := prescanTestResult("core/tee/entry_std.c", strings.Repeat("source", 80)+string(rune('a'+i)), "core/tee/tee_svc_cryp.c", "memory_call", "malloc", i+2, 20)
		for j := range r.Paths[0] {
			r.Paths[0][j].Expression = strings.Repeat("多字节", 1000)
		}
		eng.results = append(eng.results, r)
	}
	out, err := RunPrescan(context.Background(), eng, db, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Summary) > PrescanSummaryMaxBytes || strings.Count(out.Summary, " | fact_ref=") > 10 {
		t.Fatalf("summary exceeded bounds: %d", len(out.Summary))
	}
	if len(out.Fact.Paths) != 25 {
		t.Fatal("summary truncation altered full artifact")
	}
	emptyReq, emptyEng, emptyDB := prescanTestFixture(t)
	empty, err := RunPrescan(context.Background(), emptyEng, emptyDB, emptyReq)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Fact.Status != "success" || !strings.Contains(empty.Summary, "does NOT prove safety") {
		t.Fatalf("empty query became safe: %+v", empty)
	}
}

func TestPrescanSkipsMissingDBAndPersistsFailuresWithoutCreatingDB(t *testing.T) {
	for _, mode := range []string{"missing database", "query failure"} {
		t.Run(mode, func(t *testing.T) {
			req, eng, db := prescanTestFixture(t)
			if mode == "missing database" {
				db.state = codedb.StateAbsent
			} else {
				eng.err = errors.New("query timed out")
			}
			out, err := RunPrescan(context.Background(), eng, db, req)
			if err != nil {
				t.Fatal(err)
			}
			if out.Fact.Status == "success" || len(out.CoverageGaps) == 0 || out.FactRef == "" || db.ensureCalls != 0 {
				t.Fatalf("failure lost provenance: %+v", out)
			}
			if mode == "missing database" && eng.calls != 0 {
				t.Fatal("prescan analyzed an absent database")
			}
		})
	}
}

func TestPrescanPassesIndependentTimeoutAndRejectsWrongIndexScope(t *testing.T) {
	req, eng, db := prescanTestFixture(t)
	req.Timeout = time.Minute
	req.Facts.RunID = "another-run"
	eng.results = []codeql.Result{prescanTestResult("core/tee/entry_std.c", "", "core/tee/tee_svc_cryp.c", "memory_call", "memcpy", 20, 2)}
	out, err := RunPrescan(context.Background(), eng, db, req)
	if err != nil {
		t.Fatal(err)
	}
	if !eng.deadline || !strings.Contains(strings.Join(out.CoverageGaps, " "), "index scope differs") {
		t.Fatal("mismatched index influenced source metadata without a gap")
	}
}

func TestPrescanSummaryKeepsRealHeaderPathsAndIdentifiers(t *testing.T) {
	path := strings.Repeat("nested/", 40) + "entry.c"
	name := strings.Repeat("function_", 20)
	steps := []artifacts.ToolPathStep{{Location: artifacts.ToolLocation{Path: path, StartLine: 1, Symbol: name}}, {Location: artifacts.ToolLocation{Path: "sink.c", StartLine: 2}}}
	meta := PrescanResult{TotalPaths: 1, Candidates: []PrescanCandidate{{PathIndex: 0, SourceFunc: name, SinkFunc: "memcpy", Source: steps[0].Location, Sink: steps[1].Location, Hops: 2}}}
	result, _ := json.Marshal(meta)
	summary := RenderPrescanSummary(artifacts.ToolFact{Status: "success", Paths: [][]artifacts.ToolPathStep{steps}, Result: result}, "/run/taint-prescan.json")
	if !strings.Contains(summary, path) || !strings.Contains(summary, name) || len(summary) > PrescanSummaryMaxBytes {
		t.Fatal("navigation header shortened a real source path or function identifier")
	}
}
