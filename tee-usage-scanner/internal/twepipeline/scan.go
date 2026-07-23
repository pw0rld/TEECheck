// Package twepipeline wires the deterministic tail of the TWE pipeline: from a
// TrustIR candidate and a prebuilt CodeQL database, generate the query, run it,
// and solve the evidence to a verdict. It composes the M1 (twe), M2 (codeql),
// M4 (query generation), and M5 (solver) pieces — the LLM front (planner,
// expert) produces the candidate; everything here is deterministic.
package twepipeline

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/solver"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// ScanSite runs one candidate against one prebuilt database and returns the
// solver verdict. workDir is a scratch directory for the generated query pack.
//
// The candidate is validated against the TWE first (missing role or bad enum
// is a hard error — the deterministic gate at workflow step 8). A query that
// fails to run yields an Unresolved verdict rather than an error, so one bad
// site does not abort a batch.
func ScanSite(ctx context.Context, engine *codeql.Engine, catalog *twe.Catalog, cand twe.TrustIRCandidate, language, dbPath, rustLibs, workDir string) (solver.Result, error) {
	entry, ok := catalog.Get(cand.TWEID)
	if !ok {
		return solver.Solve(solver.SolveInput{Entry: twe.Entry{}, SiteID: cand.SiteID}), nil
	}
	if err := catalog.ValidateCandidate(cand); err != nil {
		return solver.Result{}, fmt.Errorf("invalid candidate: %w", err)
	}

	query, err := generateQuery(language, entry, cand)
	if err != nil {
		return solver.Result{}, err
	}
	// Pack resolution differs by language: a Rust query pack pulls transitive
	// packs only vendored in the bundle, so it needs the rust libraries on the
	// additional-packs path; cpp-all resolves top-level with none.
	depPack, additionalPacks := "codeql/rust-all", []string{rustLibs}
	if language == "cpp" {
		depPack, additionalPacks = "codeql/cpp-all", nil
	}
	queryPath, err := codeql.WriteQueryPack(workDir, "generated.ql", query, depPack)
	if err != nil {
		return solver.Result{}, err
	}

	results, err := engine.Analyze(ctx, codeql.AnalyzeOptions{
		DBPath:          dbPath,
		Queries:         []string{queryPath},
		AdditionalPacks: additionalPacks,
	})
	if err != nil {
		// Evidence is incomplete: record Unresolved, keep the error context.
		res := solver.Solve(solver.SolveInput{Entry: entry, SiteID: cand.SiteID, BuildOK: true, QueryRan: false})
		res.Reason = fmt.Sprintf("%s (analyze error: %v)", res.Reason, err)
		return res, nil
	}

	return solver.Solve(solver.SolveInput{
		Entry:            entry,
		SiteID:           cand.SiteID,
		BuildOK:          true,
		QueryRan:         true,
		Modeled:          true,
		ViolationResults: results,
	}), nil
}

// generateQuery selects the query generator by language and TWE family.
// Unhandled combinations return an explicit error rather than silently
// producing nothing.
func generateQuery(language string, entry twe.Entry, cand twe.TrustIRCandidate) (string, error) {
	switch language {
	case "rust":
		switch entry.Family {
		case twe.FamilyBinding:
			return codeql.GenerateBindingQuery(cand)
		case twe.FamilyConfig:
			return codeql.GenerateConfigQuery(cand)
		}
	}
	return "", fmt.Errorf("no query generator for %s/%s yet", language, entry.Family)
}
