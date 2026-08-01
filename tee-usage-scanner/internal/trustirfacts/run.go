package trustirfacts

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// Status values mirror schemas/trustir-tool.v1.json's "result" status enum
// exactly (success|error|unsupported|unresolved) — see the doc comment below
// on how this package chooses between error and unresolved, since the merge
// design does not spell that split out itself.
const (
	StatusSuccess     = "success"
	StatusError       = "error"
	StatusUnsupported = "unsupported"
	StatusUnresolved  = "unresolved"
)

// toolName identifies this fact layer in ToolFact.Tool. It is versioned by
// family/language in the value itself (not a separate field) because a
// future Rust/Go/JS fact layer is a different tool, not a different version
// of this one.
const toolName = "trustir-cpp"

// Run is the fact layer's single entry point: build (or reuse) the
// repository@commit database, materialize the query pack with req's
// deterministic fact table, execute the operation's query, and return the
// resulting ToolFact. It is the "main-path-callable entry" §23.3 asks for —
// a future Planner/Investigation caller (PR-06) invokes this once per
// TWE-STATE-001 site it wants evidence for; this package does not itself
// decide when to call it.
//
// Run always returns a well-formed ToolFact (never a zero value) alongside a
// nil error for every OPERATIONAL outcome, including failure: CodeQL being
// unavailable, a database build failure, a timed-out analyze, and an
// unimplemented operation/repository are all reported IN the ToolFact via
// Status, not as a Go error. A non-nil Go error means the request itself was
// malformed (see Request.validate) or the resulting fact failed schema
// validation — genuine bugs in the caller or in this package, not something
// about the target repository.
//
// Status mapping (§23.3, §23 acceptance):
//   - unsupported: this package does not (yet) implement the requested
//     operation, or has no deterministic fact table for the requested
//     repository. Never faked as success — an empty table would make the
//     thin-shell query vacuously silent, which would misreport "no
//     violation found" for a repository this package has no evidence about.
//   - unresolved: CodeQL was unavailable, or a step that call INTO CodeQL
//     failed (clone, database create, analyze) or timed out. This is the §2
//     decision-8 red line — unresolved must never be read as "no
//     vulnerability".
//   - error: reserved for this package's OWN plumbing (e.g. it could not
//     read the query file back after writing it) — a bug here, not a
//     statement about the target's evidence.
//   - success: the query ran to completion. Zero locations is a legitimate
//     success (e.g. the fixed revision, where the structural gap the query
//     looks for is genuinely absent) — see §6.5: an empty result proves
//     "no match found within the modeled scope", not "no vulnerability".
func Run(ctx context.Context, eng Engine, req Request) (artifacts.ToolFact, error) {
	if err := req.validate(); err != nil {
		return artifacts.ToolFact{}, err
	}

	base := newFact(req)

	table, ok := factTableFor(req.Repository)
	if !ok {
		return unsupportedFact(base, fmt.Sprintf("no deterministic fact table for repository %q (LLM annotation pipeline not yet built, §23.2)", req.Repository)), nil
	}
	if _, ok := operationQueries[req.Operation]; !ok {
		return unsupportedFact(base, fmt.Sprintf("operation %q not implemented by the cpp fact layer", req.Operation)), nil
	}
	if table.Empty() {
		return unsupportedFact(base, fmt.Sprintf("fact table for repository %q has no clauses", req.Repository)), nil
	}

	if eng == nil || !eng.Available() {
		return unresolvedFact(base, "codeql engine not available"), nil
	}

	dbPath := databaseDir(req.RunDir, req.Repository, req.Commit)
	reused, err := ensureDatabase(ctx, eng, req.Exec, dbPath, req.Repository, req.Commit, req.ExtraPATH)
	if err != nil {
		return unresolvedFact(base, fmt.Sprintf("database build failed: %v", err)), nil
	}

	_, queryFile, err := materializeQueryPack(req.RunDir, req.QueryPackDir, req, table)
	if err != nil {
		// Writing our own generated files failing is this package's own
		// plumbing, not evidence about the target repository.
		return errorFact(base, fmt.Sprintf("materialize query pack: %v", err)), nil
	}

	results, err := eng.Analyze(ctx, analyzeOptions(dbPath, queryFile, req.ExtraPATH))
	if err != nil {
		return unresolvedFact(base, fmt.Sprintf("analyze failed: %v", err)), nil
	}

	relDB, relErr := filepath.Rel(req.RunDir, dbPath)
	if relErr != nil {
		relDB = dbPath
	}

	fact := base
	fact.Status = StatusSuccess
	fact.Locations = toolLocations(results)
	fact.Findings = toolFindings(results)
	fact.ArtifactRef = filepath.ToSlash(relDB)
	fact.CoverageGaps = coverageGaps(reused, isLLMFactTable(req.Repository))
	return fact, nil
}

// RunAndPersist runs Run and, on success producing a fact (any status), also
// persists it — schema-validated — under the run directory (§23.3: ToolFact
// persistence). It is a convenience for callers that always want both steps;
// Run and Persist remain independently usable (e.g. a caller inspecting the
// fact before deciding whether to keep it).
func RunAndPersist(ctx context.Context, eng Engine, req Request) (artifacts.ToolFact, string, error) {
	fact, err := Run(ctx, eng, req)
	if err != nil {
		return artifacts.ToolFact{}, "", err
	}
	path, err := Persist(req.RunDir, fact)
	if err != nil {
		return fact, "", err
	}
	return fact, path, nil
}

func newFact(req Request) artifacts.ToolFact {
	return artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		// RequestID is left empty: see artifacts.ToolFact's doc comment
		// (PR-01 handoff) — there is no paired live request in a pure fact
		// model, and this package recommends dropping the field from the
		// schema in a follow-up rather than inventing a value for it here.
		RequestID:       "",
		FactID:          req.factID(),
		Tool:            toolName,
		Operation:       string(req.Operation),
		RepoCommit:      req.Commit,
		ArgumentsSHA256: req.argumentsSHA256(),
	}
}

func unsupportedFact(base artifacts.ToolFact, msg string) artifacts.ToolFact {
	base.Status = StatusUnsupported
	base.Error = msg
	return base
}

func unresolvedFact(base artifacts.ToolFact, msg string) artifacts.ToolFact {
	base.Status = StatusUnresolved
	base.Error = msg
	return base
}

func errorFact(base artifacts.ToolFact, msg string) artifacts.ToolFact {
	base.Status = StatusError
	base.Error = msg
	return base
}

// analyzeOptions builds the codeql.AnalyzeOptions for one query run.
// AdditionalPacks is deliberately nil: unlike codeql/rust-all (which needs a
// bundle's vendored library cache — see codeql.RustLibrariesPath's doc
// comment), codeql/cpp-all resolves top-level with no extra packs, per the
// existing (main-path-adjacent) precedent in
// internal/twepipeline/scan.go's generateQuery/ScanSite split.
func analyzeOptions(dbPath, queryFile, extraPATH string) codeql.AnalyzeOptions {
	return codeql.AnalyzeOptions{
		DBPath:    dbPath,
		Queries:   []string{queryFile},
		ExtraPATH: extraPATH,
	}
}

// toolLocations flattens codeql.Result into the transport-neutral
// ToolLocation shape. Symbol is left empty: internal/codeql's ParseSARIF
// flattens only the primary physical location, not the related locations
// the thin shell's `select producer, "...", ..., producer.getName(), ...`
// embeds — recovering the symbol would mean parsing the message text, which
// is fragile. This is a real, disclosed limitation, not silently dropped:
// see coverageGaps.
// toolFindings carries each result's message and the sites it names. The
// message is the query's actual conclusion — without it a caller sees a line
// number and has to guess what was concluded about it.
func toolFindings(results []codeql.Result) []artifacts.ToolFinding {
	if len(results) == 0 {
		return nil
	}
	out := make([]artifacts.ToolFinding, 0, len(results))
	for _, r := range results {
		fi := artifacts.ToolFinding{
			Message:  r.Message,
			Location: artifacts.ToolLocation{Path: r.Path, StartLine: r.StartLine, EndLine: r.EndLine},
		}
		for _, rel := range r.Related {
			fi.Related = append(fi.Related, artifacts.ToolLocation{
				Path: rel.Path, StartLine: rel.StartLine, Symbol: rel.Symbol,
			})
		}
		out = append(out, fi)
	}
	return out
}

func toolLocations(results []codeql.Result) []artifacts.ToolLocation {
	if len(results) == 0 {
		return nil
	}
	out := make([]artifacts.ToolLocation, 0, len(results))
	for _, r := range results {
		out = append(out, artifacts.ToolLocation{
			Path:      r.Path,
			StartLine: r.StartLine,
			EndLine:   r.EndLine,
		})
	}
	return out
}

// coverageGaps records this slice's known, disclosed limitations (§6.5: the
// fact layer proves what it modeled, and must say what it did not) rather
// than letting a consumer assume the modeled scope is complete.
func coverageGaps(dbReused, llmSourced bool) []string {
	factTableGap := "fact table is a deterministic hand-authored fixture (§23.2 first slice); no LLM annotation was registered for this repository"
	if llmSourced {
		factTableGap = "fact table was produced by the LLM annotation -> resolver pipeline (annotate.go/resolver.go); unresolved annotations were dropped before this run, see the AnnotationReport from that call for what was rejected"
	}
	gaps := []string{
		factTableGap,
		"only the STATE/rollback family (TWE-STATE-001) is implemented; the other six TWE families are unsupported",
		"database built with --build-mode=none: macro/#ifdef branches resolve to source defaults, not a real build (§23.5)",
		"path/line only for the primary location; a finding's named sites carry resolved symbols, other locations do not",
	}
	if dbReused {
		gaps = append(gaps, "database reused from a prior build in this run directory (cache hit on repository+commit)")
	}
	return gaps
}
