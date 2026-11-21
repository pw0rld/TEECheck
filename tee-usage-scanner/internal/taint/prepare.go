package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func NormalizeRequest(req Request) (Request, error) {
	if !validIdentifier(req.SourceFunc) {
		return req, fmt.Errorf("source_func must be a C identifier")
	}
	if req.SourcePath != "" && !validSourcePath(req.SourcePath) {
		return req, fmt.Errorf("source_path must be a normalized repository-relative path")
	}
	if req.SourceParamIndex < -1 {
		return req, fmt.Errorf("source_param_index must be -1 or non-negative")
	}
	if req.SinkFunc != "" && !validIdentifier(req.SinkFunc) {
		return req, fmt.Errorf("sink_func must be a C identifier")
	}
	if req.SinkFunc == "" && req.SinkKind == "" {
		return req, fmt.Errorf("provide sink_func or sink_kind")
	}
	switch req.SinkKind {
	case "", "memory_copy", "array_index", "pointer_deref", "function_call":
	default:
		return req, fmt.Errorf("unsupported sink_kind %q", req.SinkKind)
	}
	if req.SinkKind == "function_call" && req.SinkFunc == "" {
		return req, fmt.Errorf("function_call requires sink_func")
	}
	if req.SinkFunc != "" && req.SinkKind != "" && req.SinkKind != "function_call" && req.SinkKind != "memory_copy" {
		return req, fmt.Errorf("sink_func can only refine memory_copy or function_call; omit sink_func for expression sinks")
	}
	if len(req.BarrierFuncs) > 8 {
		return req, fmt.Errorf("at most 8 barrier_funcs are allowed")
	}
	barriers := map[string]bool{}
	for _, name := range req.BarrierFuncs {
		if !validIdentifier(name) {
			return req, fmt.Errorf("barrier_funcs must contain C identifiers")
		}
		barriers[name] = true
	}
	req.BarrierFuncs = nil
	for name := range barriers {
		req.BarrierFuncs = append(req.BarrierFuncs, name)
	}
	sort.Strings(req.BarrierFuncs)
	if req.MaxPaths == 0 {
		req.MaxPaths = 5
	}
	if req.MaxHops == 0 {
		req.MaxHops = 12
	}
	if req.MaxPaths < 1 || req.MaxPaths > 10 {
		return req, fmt.Errorf("max_paths must be between 1 and 10")
	}
	if req.MaxHops < 1 || req.MaxHops > 20 {
		return req, fmt.Errorf("max_hops must be between 1 and 20")
	}
	return req, nil
}

func validIdentifier(s string) bool { return len(s) <= 256 && identifier.MatchString(s) }
func validSourcePath(s string) bool {
	return len(s) <= 4096 && !filepath.IsAbs(s) && !strings.Contains(s, "\\") && s != "." && s != ".." && !strings.HasPrefix(s, "../") && filepath.ToSlash(filepath.Clean(s)) == s
}

// Prepare performs no tool calls. It binds the source and computes identity
// before the planner spends its query quota or checks the run-local cache.
func (s *Service) Prepare(runDir, repoRoot, repository, commit string, req Request) (Prepared, error) {
	var p Prepared
	req, err := NormalizeRequest(req)
	if err != nil {
		return p, err
	}
	if runDir == "" || repoRoot == "" || repository == "" || commit == "" || commit == "unknown" {
		return p, fmt.Errorf("trace_taint requires a run and pinned repository/commit")
	}
	runDir, err = filepath.Abs(runDir)
	if err != nil {
		return p, err
	}
	repoRoot, err = filepath.Abs(repoRoot)
	if err != nil {
		return p, err
	}
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		return p, fmt.Errorf("load trace manifest: %w", err)
	}
	if codedb.NormalizeRepo(manifest.RepoURL) != codedb.NormalizeRepo(repository) || manifest.Commit != commit {
		return p, fmt.Errorf("trace identity differs from run manifest")
	}
	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		return p, fmt.Errorf("trace source requires the program index: %w", err)
	}
	if facts.Capabilities.Symbols != artifacts.CapabilityAvailable && facts.Capabilities.Symbols != artifacts.CapabilityPartial {
		return p, fmt.Errorf("trace source requires indexed definitions")
	}
	scope := manifest.Scope
	if scope.Commit == "" {
		scope = runfs.BuildScope(repository, commit, repoRoot)
	}
	if facts.Scope.Commit != scope.Commit || (facts.Scope.RepoURL != "" && codedb.NormalizeRepo(facts.Scope.RepoURL) != codedb.NormalizeRepo(scope.RepoURL)) || (facts.Scope.Hash != "" && scope.Hash != "" && facts.Scope.Hash != scope.Hash) {
		return p, fmt.Errorf("trace program index belongs to another scope")
	}
	var matches []artifacts.Symbol
	for _, symbol := range facts.Symbols {
		if symbol.Name == req.SourceFunc && (req.SourcePath == "" || symbol.File == req.SourcePath) {
			matches = append(matches, symbol)
		}
	}
	if len(matches) != 1 {
		return p, fmt.Errorf("source_func resolves to %d definitions; use source_path to select a unique indexed definition", len(matches))
	}
	source := matches[0]
	if !validSourcePath(source.File) || source.StartLine < 1 {
		return p, fmt.Errorf("indexed source has no valid source anchor")
	}
	bound, err := contracts.BindSubject(artifacts.ContractSubject{Path: source.File, Symbol: source.Name, SymbolID: source.SymbolID}, contracts.BindingContext{RunDir: runDir, RepoRoot: repoRoot, Scope: scope, RepoFacts: &facts})
	if err != nil {
		return p, fmt.Errorf("bind trace source: %w", err)
	}
	req.SourcePath = source.File
	query, err := BuildQuery(req.Parameters, source)
	if err != nil {
		return p, err
	}
	identity := struct {
		Version    string
		Scope      artifacts.ScannedScope
		Source     artifacts.Symbol
		SourceHash string
		Parameters Parameters
		QueryHash  string
	}{QueryVersion, scope, source, bound.ContentSHA256, req.Parameters, digest([]byte(query))}
	// Root paths do not change the logical query, but runDir is a separate
	// cache namespace below: no artifact may be borrowed from another run.
	identity.Scope.Root = ""
	body, _ := json.Marshal(identity)
	p = Prepared{Key: digest(body), Request: req, Source: source, SourceHash: bound.ContentSHA256, Scope: scope, RunDir: runDir, RepoRoot: repoRoot, Repository: repository, Commit: commit, query: query}
	return p, nil
}

func digest(data []byte) string  { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func cacheKey(p Prepared) string { return p.RunDir + "\x00" + p.Key }
