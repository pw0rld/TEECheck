package codeql

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// Adapter bridges the staticcheck.Adapter interface to the CodeQL fact engine.
// Unlike a single-shot scanner (grep, semgrep), CodeQL runs against a prebuilt
// database, so Run requires a database path and query modules via ExtraArgs:
//
//	database         (required) path to a prebuilt CodeQL database
//	queries          (required) query files/dirs/suites, comma or space separated
//	additional_packs (optional) package search paths, comma separated
//	codeql_bin       (optional) explicit codeql binary path
//	extra_path       (optional) prepended to PATH (e.g. so the Rust extractor finds cargo)
//
// The TWE pipeline (M3+) calls internal/codeql.Engine directly; this adapter
// keeps CodeQL reachable through the legacy static-tool path too.
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "codeql" }

func (a *Adapter) Available() bool { return codeql.New().Available() }

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	dbPath := req.ExtraArgs["database"]
	if dbPath == "" {
		return nil, fmt.Errorf("codeql: a prebuilt database is required (set ExtraArgs[\"database\"]); CodeQL is not a single-shot scanner")
	}
	queries := splitList(req.ExtraArgs["queries"])
	if len(queries) == 0 {
		return nil, fmt.Errorf("codeql: at least one query is required (set ExtraArgs[\"queries\"])")
	}

	engine := codeql.NewWithBin(req.ExtraArgs["codeql_bin"])
	results, err := engine.Analyze(ctx, codeql.AnalyzeOptions{
		DBPath:          dbPath,
		Queries:         queries,
		AdditionalPacks: splitList(req.ExtraArgs["additional_packs"]),
		ExtraPATH:       req.ExtraArgs["extra_path"],
	})
	if err != nil {
		return nil, err
	}

	findings := make([]staticcheck.CheckFinding, 0, len(results))
	for _, r := range results {
		findings = append(findings, staticcheck.CheckFinding{
			ToolName:  "codeql",
			RuleID:    r.RuleID,
			Path:      r.Path,
			StartLine: r.StartLine,
			EndLine:   r.EndLine,
			Message:   r.Message,
			Severity:  normalizeSeverity(r.Level),
		})
	}
	return findings, nil
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func normalizeSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "note", "info":
		return "info"
	default:
		return ""
	}
}
