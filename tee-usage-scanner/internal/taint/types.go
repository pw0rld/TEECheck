// Package taint executes fixed, parameterized CodeQL may-flow queries.
// Its results are immutable tool evidence, never vulnerability verdicts.
package taint

import (
	"context"
	"sync"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

const Operation = artifacts.TaintTraceOperation
const QueryVersion = "teecheck.cpp.taint.v1"

const ZeroPathNotice = "0 taint paths found under --build-mode=none (macros, function pointers, assembly, or missing headers may break flow; this does NOT prove safety)."

type Parameters struct {
	SourceFunc       string   `json:"source_func"`
	SourcePath       string   `json:"source_path,omitempty"`
	SourceParamIndex int      `json:"source_param_index"`
	SinkFunc         string   `json:"sink_func,omitempty"`
	SinkKind         string   `json:"sink_kind,omitempty"`
	BarrierFuncs     []string `json:"barrier_funcs,omitempty"`
}

type Request struct {
	Parameters
	MaxPaths int `json:"max_paths"`
	MaxHops  int `json:"max_hops"`
}

type Engine interface {
	Available() bool
	Analyze(context.Context, codeql.AnalyzeOptions) ([]codeql.Result, error)
}

type Prepared struct {
	Key        string
	Request    Request
	Source     artifacts.Symbol
	SourceHash string
	Scope      artifacts.ScannedScope
	RunDir     string
	RepoRoot   string
	Repository string
	Commit     string
	query      string
}

type cacheEntry struct {
	fact       artifacts.ToolFact
	path       string
	fileHash   string
	sourceHash string
}

// Service is shared by one run's registry, including all planner samples.
// The DB provider is the same instance used by the normal program index.
type Service struct {
	Engine Engine
	DB     codedb.DatabaseProvider
	mu     sync.Mutex
	cache  map[string]cacheEntry
}

func NewService(engine Engine, db codedb.DatabaseProvider) *Service {
	return &Service{Engine: engine, DB: db, cache: map[string]cacheEntry{}}
}

type Result struct {
	QueryVersion        string              `json:"query_version"`
	Parameters          Parameters          `json:"parameters"`
	Source              artifacts.Symbol    `json:"source"`
	SourceSHA256        string              `json:"source_sha256"`
	QuerySHA256         string              `json:"query_sha256"`
	TotalPaths          int                 `json:"total_paths"`
	ResultCount         int                 `json:"result_count"`
	ResultsWithoutPaths int                 `json:"results_without_paths,omitempty"`
	ElapsedMS           int64               `json:"elapsed_ms"`
	BarriersApplied     []string            `json:"barriers_applied"`
	PathEnumeration     string              `json:"path_enumeration"`
	MalformedPaths      [][]codeql.PathStep `json:"malformed_paths,omitempty"`
	AnalysisPathLimit   int                 `json:"analysis_paths_per_result"`
}
