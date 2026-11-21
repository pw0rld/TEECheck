package taint

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func (s *Service) Cached(p Prepared) (artifacts.ToolFact, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cached(p)
}

func (s *Service) cached(p Prepared) (artifacts.ToolFact, string, bool) {
	entry, ok := s.cache[cacheKey(p)]
	if !ok {
		// A resumed process has an empty in-memory map. Recover only the exact
		// persisted query identity after independently validating all bindings.
		path := preparedFactPath(p)
		if path == "" {
			return artifacts.ToolFact{}, "", false
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return artifacts.ToolFact{}, "", false
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return artifacts.ToolFact{}, "", false
		}
		var fact artifacts.ToolFact
		if json.Unmarshal(body, &fact) != nil || !matchesPreparedFact(fact, p) {
			return artifacts.ToolFact{}, "", false
		}
		entry = cacheEntry{copyFact(fact), path, digest(body), p.SourceHash}
		if s.cache == nil {
			s.cache = map[string]cacheEntry{}
		}
		s.cache[cacheKey(p)] = entry
	}
	if entry.sourceHash != p.SourceHash {
		return artifacts.ToolFact{}, "", false
	}
	body, err := os.ReadFile(entry.path)
	if err != nil || digest(body) != entry.fileHash || artifacts.ValidateToolFactContent(entry.fact) != nil {
		return artifacts.ToolFact{}, "", false
	}
	return copyFact(entry.fact), entry.path, true
}

// Run executes at most one query for a prepared identity, then atomically
// publishes immutable evidence. Failed queries are recorded under distinct
// identities and are not cached, so a transient failure can be retried.
func (s *Service) Run(ctx context.Context, p Prepared) (artifacts.ToolFact, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fact, path, ok := s.cached(p); ok {
		return fact, path, nil
	}
	if _, existed := s.cache[cacheKey(p)]; existed {
		return artifacts.ToolFact{}, "", fmt.Errorf("cached ToolFact changed or became unreadable; refusing to overwrite immutable evidence")
	}
	if preparedFactPath(p) == "" {
		return artifacts.ToolFact{}, "", fmt.Errorf("trace request was not prepared")
	}
	if _, err := os.Lstat(preparedFactPath(p)); err == nil || !os.IsNotExist(err) {
		return artifacts.ToolFact{}, "", fmt.Errorf("persisted ToolFact is invalid or unreadable; refusing to overwrite immutable evidence")
	}
	started := time.Now()
	meta := Result{QueryVersion: QueryVersion, Parameters: p.Request.Parameters, Source: p.Source, SourceSHA256: p.SourceHash, QuerySHA256: digest([]byte(p.query)), BarriersApplied: append([]string{}, p.Request.BarrierFuncs...), PathEnumeration: "CodeQL-emitted path witnesses; not exhaustive enumeration and not a shortest-path guarantee", AnalysisPathLimit: 10}
	scope := p.Scope
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, RequestID: p.Key, FactID: "taint-" + p.Key, Tool: "codeql-cpp-taint", Operation: Operation, RepoCommit: p.Commit, ArgumentsSHA256: p.Key, Scope: &scope, Status: "success", Locations: []artifacts.ToolLocation{}, CoverageGaps: []string{
		"Potential data flow in a --build-mode=none graph does not establish runtime reachability or a security violation.",
		"Macros, indirect calls, assembly, missing headers, build configuration and external models may omit paths.",
		"CodeQL emits a bounded set of path witnesses per result; total_paths counts those witnesses, not every possible program path.",
		"Only the selected definition's parameter values and one-level pointer contents are sources; deeper indirections and output aliases may need additional models.",
	}}
	if len(p.Request.BarrierFuncs) > 0 {
		fact.CoverageGaps = append(fact.CoverageGaps, "barrier_funcs are syntactic filters on call-result nodes, not verified guards or proof of safety.")
	}
	finish := func(status, message string) (artifacts.ToolFact, string, error) {
		fact.Status, fact.Error = status, message
		meta.ElapsedMS = time.Since(started).Milliseconds()
		if meta.TotalPaths == 0 && status == "success" {
			fact.CoverageGaps = append(fact.CoverageGaps, ZeroPathNotice)
		}
		fact.Result, _ = json.Marshal(meta)
		if status != "success" {
			fact.FactID += "-" + digest(append([]byte(status+message), fact.Result...))[:16]
		}
		fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
		path, err := trustirfacts.Persist(p.RunDir, fact)
		if err != nil {
			return fact, "", err
		}
		if status == "success" {
			body, err := os.ReadFile(path)
			if err != nil {
				return fact, path, err
			}
			if s.cache == nil {
				s.cache = map[string]cacheEntry{}
			}
			s.cache[cacheKey(p)] = cacheEntry{copyFact(fact), path, digest(body), p.SourceHash}
		}
		return fact, path, nil
	}
	if s.Engine == nil || !s.Engine.Available() {
		return finish("unsupported", "CodeQL engine unavailable")
	}
	if s.DB == nil {
		return finish("unsupported", "shared CodeQL database provider unavailable")
	}
	if err := ctx.Err(); err != nil {
		return finish("unresolved", err.Error())
	}
	dbPath, err := s.DB.Ensure(ctx, codedb.Scope{RunDir: p.RunDir, Repository: p.Repository, Commit: p.Commit})
	if err != nil {
		return finish("unresolved", "CodeQL database unavailable: "+err.Error())
	}
	packDir := filepath.Join(p.RunDir, "02_tool_facts", "trustir", "queries", "taint-"+p.Key)
	if err := os.MkdirAll(packDir, 0755); err != nil {
		return fact, "", err
	}
	queryPath := filepath.Join(packDir, "TraceTaint.ql")
	if err := os.WriteFile(queryPath, []byte(p.query), 0644); err != nil {
		return fact, "", err
	}
	pack := "name: teecheck/runtime-taint\nversion: 0.0.1\ndependencies:\n  codeql/cpp-all: 7.0.0\n"
	if err := os.WriteFile(filepath.Join(packDir, "qlpack.yml"), []byte(pack), 0644); err != nil {
		return fact, "", err
	}
	if v, ok := s.Engine.(interface {
		Version(context.Context) (string, error)
	}); ok {
		fact.ToolVersion, _ = v.Version(ctx)
	}
	results, err := s.Engine.Analyze(ctx, codeql.AnalyzeOptions{DBPath: dbPath, Queries: []string{queryPath}, MaxPaths: 10})
	if err != nil {
		return finish("unresolved", "CodeQL taint analysis failed: "+err.Error())
	}
	meta.ResultCount = len(results)
	seen := map[string]bool{}
	for _, result := range results {
		if len(result.Paths) == 0 {
			meta.ResultsWithoutPaths++
		}
		for _, raw := range result.Paths {
			meta.TotalPaths++
			path, ok := canonicalPath(raw, p.RepoRoot)
			if !ok {
				meta.MalformedPaths = append(meta.MalformedPaths, raw)
				continue
			}
			body, _ := json.Marshal(path)
			key := string(body)
			if !seen[key] {
				seen[key] = true
				fact.Paths = append(fact.Paths, path)
			}
		}
	}
	sort.Slice(fact.Paths, func(i, j int) bool {
		if len(fact.Paths[i]) != len(fact.Paths[j]) {
			return len(fact.Paths[i]) < len(fact.Paths[j])
		}
		a, _ := json.Marshal(fact.Paths[i])
		b, _ := json.Marshal(fact.Paths[j])
		return string(a) < string(b)
	})
	for _, path := range fact.Paths {
		fact.Locations = append(fact.Locations, path[len(path)-1].Location)
	}
	if len(meta.MalformedPaths) > 0 {
		fact.CoverageGaps = append(fact.CoverageGaps, fmt.Sprintf("%d CodeQL path witnesses have missing locations; raw nodes are preserved in result.malformed_paths and omitted from source-addressable paths", len(meta.MalformedPaths)))
	}
	if meta.ResultsWithoutPaths > 0 {
		fact.CoverageGaps = append(fact.CoverageGaps, fmt.Sprintf("%d CodeQL result(s) had no path witnesses; their missing paths are not negative evidence", meta.ResultsWithoutPaths))
	}
	// The complete, deduplicated witness set is retained on disk. Display
	// max_paths/max_hops must never truncate this immutable artifact.
	meta.TotalPaths = len(fact.Paths) + len(meta.MalformedPaths)
	if len(results) > 0 && len(fact.Paths) == 0 {
		return finish("unresolved", "CodeQL returned results without source-addressable path witnesses")
	}
	return finish("success", "")
}

func canonicalPath(raw []codeql.PathStep, root string) ([]artifacts.ToolPathStep, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	path := make([]artifacts.ToolPathStep, 0, len(raw))
	for i, node := range raw {
		if node.Path == "" || node.StartLine < 1 {
			return nil, false
		}
		location := node.Path
		uri, err := url.Parse(location)
		if err != nil || (uri.Scheme != "" && uri.Scheme != "file") || (uri.Scheme == "file" && uri.Host != "" && uri.Host != "localhost") {
			return nil, false
		}
		if uri.Scheme == "file" {
			location = uri.Path
		} else if unescaped, err := url.PathUnescape(location); err == nil {
			location = unescaped
		} else {
			return nil, false
		}
		if strings.ContainsRune(location, 0) || strings.Contains(location, "\\") {
			return nil, false
		}
		for _, part := range strings.Split(filepath.ToSlash(location), "/") {
			if part == ".." {
				return nil, false
			}
		}
		if filepath.IsAbs(location) {
			rel, err := filepath.Rel(root, location)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, false
			}
			location = rel
		}
		location = filepath.ToSlash(filepath.Clean(location))
		if !validSourcePath(location) {
			return nil, false
		}
		kind := "flow"
		if i == 0 {
			kind = "source"
		}
		if i == len(raw)-1 {
			kind = "sink"
		}
		path = append(path, artifacts.ToolPathStep{Kind: kind, Location: artifacts.ToolLocation{Path: filepath.ToSlash(location), StartLine: node.StartLine, EndLine: node.EndLine, Symbol: node.Function}, Message: node.Expression})
	}
	return path, true
}

func copyFact(f artifacts.ToolFact) artifacts.ToolFact {
	body, _ := json.Marshal(f)
	var out artifacts.ToolFact
	_ = json.Unmarshal(body, &out)
	return out
}

func preparedFactPath(p Prepared) string {
	key, err := hex.DecodeString(p.Key)
	if err != nil || len(key) != 32 || p.query == "" || p.RunDir == "" || p.SourceHash == "" {
		return ""
	}
	return runfs.TrustIRToolFactPath(p.RunDir, "taint-"+p.Key)
}
func matchesPreparedFact(f artifacts.ToolFact, p Prepared) bool {
	if f.SchemaVersion != artifacts.SchemaVersionToolFactV1 || f.Status != "success" || f.Operation != Operation || f.Tool != "codeql-cpp-taint" || f.RequestID != p.Key || f.FactID != "taint-"+p.Key || f.ArgumentsSHA256 != p.Key || f.RepoCommit != p.Commit || f.Scope == nil || !reflect.DeepEqual(*f.Scope, p.Scope) || artifacts.ValidateToolFactContent(f) != nil {
		return false
	}
	var result Result
	if json.Unmarshal(f.Result, &result) != nil {
		return false
	}
	return result.QueryVersion == QueryVersion && result.SourceSHA256 == p.SourceHash && result.QuerySHA256 == digest([]byte(p.query)) && reflect.DeepEqual(result.Source, p.Source) && reflect.DeepEqual(result.Parameters, p.Request.Parameters)
}
