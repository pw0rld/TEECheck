package taint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

const PrescanOperation = artifacts.TaintPrescanOperation
const PrescanQueryVersion = "teecheck.cpp.entry_taint.v1"
const PrescanSummaryMaxBytes = 12 << 10
const DefaultPrescanTimeout = 5 * time.Minute

type PrescanRequest struct {
	RunDir, RepoRoot, Repository, Commit, QueryPath string
	Timeout                                         time.Duration
	Facts                                           *artifacts.RepoFacts
}

type PrescanOutput struct {
	Fact             artifacts.ToolFact
	FactRef, Summary string
	CoverageGaps     []string
}

// PrescanCandidate ranks a witness for navigation, not exploitability. PathIndex
// points into the complete immutable ToolFact.Paths array.
type PrescanCandidate struct {
	PathIndex    int                    `json:"path_index"`
	SourceFunc   string                 `json:"source_func"`
	SinkFunc     string                 `json:"sink_func"`
	SourceSignal string                 `json:"source_signal,omitempty"`
	SinkKind     string                 `json:"sink_kind,omitempty"`
	Source       artifacts.ToolLocation `json:"source"`
	Sink         artifacts.ToolLocation `json:"sink"`
	Hops         int                    `json:"hops"`
	Score        int                    `json:"navigation_score"`
}

type PrescanResult struct {
	QueryVersion        string              `json:"query_version"`
	QuerySHA256         string              `json:"query_sha256,omitempty"`
	TreeContentSHA256   string              `json:"tree_content_sha256,omitempty"`
	ResultCount         int                 `json:"result_count"`
	TotalPaths          int                 `json:"total_paths"`
	RawWitnessCount     int                 `json:"raw_witness_count"`
	ResultsWithoutPaths int                 `json:"results_without_paths,omitempty"`
	MalformedPaths      [][]codeql.PathStep `json:"malformed_paths,omitempty"`
	Candidates          []PrescanCandidate  `json:"ranked_candidates"`
	ElapsedMS           int64               `json:"elapsed_ms"`
	PathEnumeration     string              `json:"path_enumeration"`
	AnalysisPathLimit   int                 `json:"analysis_paths_per_result"`
}

// RunPrescan runs one checked-in batch query against an already-ready private
// database. It never creates a database, promotes a case, or produces a verdict.
// Repeated calls recover the exact immutable run-local artifact; corruption is
// rejected rather than overwritten. Operational failures are persisted as facts.
func RunPrescan(ctx context.Context, eng Engine, db codedb.DatabaseProvider, req PrescanRequest) (PrescanOutput, error) {
	started := time.Now()
	if req.Timeout <= 0 {
		req.Timeout = DefaultPrescanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	var err error
	if req.RunDir, err = filepath.Abs(req.RunDir); err != nil {
		return PrescanOutput{}, err
	}
	if req.RepoRoot, err = filepath.Abs(req.RepoRoot); err != nil {
		return PrescanOutput{}, err
	}
	manifest, err := runfs.LoadManifest(req.RunDir)
	if err != nil {
		return PrescanOutput{}, fmt.Errorf("prescan manifest: %w", err)
	}
	if req.Repository == "" || req.Commit == "" || manifest.RepoURL != req.Repository || manifest.Commit != req.Commit {
		return PrescanOutput{}, fmt.Errorf("prescan repository/commit differs from manifest")
	}
	scope := runfs.BuildScope(req.Repository, req.Commit, req.RepoRoot)
	if manifest.Scope.Hash != "" && (manifest.Scope.Hash != scope.Hash || manifest.Scope.RepoURL != scope.RepoURL || manifest.Scope.Commit != scope.Commit) {
		return PrescanOutput{}, fmt.Errorf("prescan source scope differs from manifest")
	}
	root, rootErr := filepath.EvalSymlinks(req.RepoRoot)
	manifestRoot, manifestRootErr := filepath.EvalSymlinks(manifest.LocalPath)
	if rootErr != nil || manifestRootErr != nil || root != manifestRoot {
		return PrescanOutput{}, fmt.Errorf("prescan source root differs from manifest")
	}
	meta := PrescanResult{QueryVersion: PrescanQueryVersion, Candidates: []PrescanCandidate{}, AnalysisPathLimit: 10,
		PathEnumeration: "CodeQL-emitted may-flow witnesses, not exhaustive paths, globally shortest paths, runtime reachability, or security verdicts"}
	queryPath, queryErr := filepath.Abs(req.QueryPath)
	var query []byte
	if queryErr == nil {
		query, queryErr = os.ReadFile(queryPath)
	}
	if queryErr == nil {
		meta.QuerySHA256 = digest(query)
	}
	status, message, version := "success", "", "unreported"
	if eng == nil || !eng.Available() {
		status, message = "unsupported", "CodeQL engine unavailable; entry taint prescan was not executed"
	}
	if db == nil || db.State(codedb.Scope{RunDir: req.RunDir, Repository: req.Repository, Commit: req.Commit}) != codedb.StateReady {
		status, message = "unsupported", "CodeQL database is not ready; entry taint prescan did not create or rebuild a database"
	}
	if status == "success" && queryErr != nil {
		status, message = "unresolved", "Static entry taint query unavailable: "+queryErr.Error()
	}
	if status == "success" {
		if reporter, ok := eng.(interface {
			Version(context.Context) (string, error)
		}); ok {
			version, err = reporter.Version(ctx)
			if err != nil || strings.TrimSpace(version) == "" {
				status, message = "unresolved", "CodeQL version could not be established for entry taint prescan"
			}
		}
		if status == "success" {
			meta.TreeContentSHA256, err = sourcehash.TreeExcluding(req.RepoRoot, []string{req.RunDir})
			if err != nil {
				status, message = "unresolved", "Prescan source contents could not be fingerprinted: "+err.Error()
			}
		}
	}
	keyBody, _ := json.Marshal(struct {
		Scope                                         artifacts.ScannedScope
		Query, Tree, Version, Schema, Status, Message string
	}{scope, meta.QuerySHA256, meta.TreeContentSHA256, version, PrescanQueryVersion, status, message})
	key := digest(keyBody)
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, RequestID: key, FactID: "taint-prescan-" + key,
		Tool: "codeql-cpp-entry-taint", ToolVersion: version, Operation: PrescanOperation, RepoCommit: req.Commit, ArgumentsSHA256: key,
		Scope: &scope, Status: status, Locations: []artifacts.ToolLocation{}, CoverageGaps: []string{
			"Entry-surface signals and may-flow witnesses are navigation clues, not proof of external reachability, attacker control, missing guards, or a security violation.",
			"Macros, indirect calls, assembly, missing headers, extraction configuration, and external models can omit data flow; absence of paths is not proof of safety.",
			"Counts and shortest-first choices describe emitted CodeQL witnesses; --max-paths limits witnesses per result and does not enumerate all possible paths.",
		}}
	if version == "unreported" {
		fact.CoverageGaps = append(fact.CoverageGaps, "The injected analysis engine did not report its version.")
	}
	if req.Facts != nil && (req.Facts.RunID != manifest.RunID || !reflect.DeepEqual(req.Facts.Scope, scope)) {
		fact.CoverageGaps = append(fact.CoverageGaps, "Program index scope differs from this prescan; its symbol names and entry signals were not used for ranking.")
		req.Facts = nil
	}
	path := runfs.TrustIRToolFactPath(req.RunDir, fact.FactID)
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return PrescanOutput{}, fmt.Errorf("prescan evidence is not a regular immutable artifact")
		}
		var previous artifacts.ToolFact
		if err = runfs.ReadJSON(path, &previous); err != nil {
			return PrescanOutput{}, fmt.Errorf("read immutable prescan evidence: %w", err)
		}
		var old PrescanResult
		if previous.Operation != PrescanOperation || previous.FactID != fact.FactID || previous.ArgumentsSHA256 != key || previous.RepoCommit != req.Commit || previous.ToolVersion != version || previous.Scope == nil || !reflect.DeepEqual(*previous.Scope, scope) || artifacts.ValidateToolFactContent(previous) != nil || json.Unmarshal(previous.Result, &old) != nil || old.QuerySHA256 != meta.QuerySHA256 || old.TreeContentSHA256 != meta.TreeContentSHA256 || old.QueryVersion != PrescanQueryVersion {
			return PrescanOutput{}, fmt.Errorf("persisted prescan ToolFact failed identity/content validation; refusing overwrite")
		}
		return prescanOutput(previous, path), nil
	} else if !os.IsNotExist(statErr) {
		return PrescanOutput{}, statErr
	}
	finish := func() (PrescanOutput, error) {
		meta.ElapsedMS = time.Since(started).Milliseconds()
		if fact.Status != "success" {
			fact.CoverageGaps = append(fact.CoverageGaps, fact.Error, "Prescan failure is not a successful empty search and does not prove safety.")
		}
		if fact.Status == "success" && meta.TotalPaths == 0 {
			fact.CoverageGaps = append(fact.CoverageGaps, ZeroPathNotice)
		}
		fact.Result, _ = json.Marshal(meta)
		fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
		written, err := trustirfacts.Persist(req.RunDir, fact)
		if err != nil {
			return PrescanOutput{}, err
		}
		return prescanOutput(fact, written), nil
	}
	if status != "success" {
		fact.Error = message
		return finish()
	}
	if err = ctx.Err(); err != nil {
		fact.Status, fact.Error = "unresolved", err.Error()
		return finish()
	}
	results, err := eng.Analyze(ctx, codeql.AnalyzeOptions{DBPath: db.Path(codedb.Scope{RunDir: req.RunDir, Repository: req.Repository, Commit: req.Commit}), Queries: []string{queryPath}, MaxPaths: 10})
	if err != nil {
		fact.Status, fact.Error = "unresolved", "Entry taint prescan query failed: "+err.Error()
		return finish()
	}
	if after, err := sourcehash.TreeExcluding(req.RepoRoot, []string{req.RunDir}); err != nil || after != meta.TreeContentSHA256 {
		fact.Status, fact.Error = "unresolved", "Source contents changed during entry taint prescan; path evidence was not adopted"
		return finish()
	}
	meta.ResultCount = len(results)
	seen := map[string]int{}
	var candidates []PrescanCandidate
	for _, result := range results {
		if len(result.Paths) == 0 {
			meta.ResultsWithoutPaths++
		}
		for _, raw := range result.Paths {
			meta.RawWitnessCount++
			steps, ok := canonicalPath(raw, req.RepoRoot)
			if !ok {
				meta.MalformedPaths = append(meta.MalformedPaths, raw)
				continue
			}
			for i := range steps {
				if steps[i].Location.Symbol == "" {
					steps[i].Location.Symbol = prescanSymbol(req.Facts, steps[i].Location)
				}
			}
			body, _ := json.Marshal(steps)
			identity := string(body)
			index, exists := seen[identity]
			if !exists {
				index = len(fact.Paths)
				seen[identity] = index
				fact.Paths = append(fact.Paths, steps)
			}
			candidates = append(candidates, prescanCandidate(steps, index, result.Message, req.Facts))
		}
	}
	meta.TotalPaths = len(fact.Paths)
	meta.Candidates = RankPrescanCandidates(candidates)
	for _, steps := range fact.Paths {
		fact.Locations = append(fact.Locations, steps[len(steps)-1].Location)
	}
	if len(meta.MalformedPaths) > 0 {
		fact.CoverageGaps = append(fact.CoverageGaps, fmt.Sprintf("%d malformed path witnesses retained in result.malformed_paths and omitted from source-addressable candidates.", len(meta.MalformedPaths)))
	}
	if meta.ResultsWithoutPaths > 0 {
		fact.CoverageGaps = append(fact.CoverageGaps, fmt.Sprintf("%d result(s) had no path witnesses; missing witnesses are not negative evidence.", meta.ResultsWithoutPaths))
	}
	if len(results) > 0 && len(fact.Paths) == 0 {
		fact.Status, fact.Error = "unresolved", "CodeQL returned results without source-addressable path witnesses"
	}
	// Sort candidate ties independently of map and SARIF encounter order.
	sort.Slice(fact.Locations, func(i, j int) bool {
		a, b := fact.Locations[i], fact.Locations[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.StartLine < b.StartLine
	})
	return finish()
}

func prescanOutput(fact artifacts.ToolFact, path string) PrescanOutput {
	return PrescanOutput{Fact: fact, FactRef: path, Summary: RenderPrescanSummary(fact, path), CoverageGaps: append([]string(nil), fact.CoverageGaps...)}
}
