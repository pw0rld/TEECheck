package repoindex

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// TableQuerier is the slice of the CodeQL engine this package needs. Declared
// here rather than imported so a test can drive the decode path with canned
// tables and no CodeQL binary.
type TableQuerier interface {
	QueryTable(ctx context.Context, opts codeql.QueryTableOptions) ([][]string, error)
}

// Query file names, in the pack at codeql/index/cpp.
const (
	querySymbols         = "Symbols.ql"
	queryCallEdges       = "CallEdges.ql"
	queryUnresolved      = "UnresolvedCalls.ql"
	queryFieldAccesses   = "FieldAccesses.ql"
	queryCallSiteCounts  = "CallSiteCounts.ql"
	indexQueryPackSubdir = "index"
)

// QueryPackDir resolves the index query pack from the knowledge root, the
// same way the planner resolves the TrustIR pack: the fixed layout puts
// knowledge/ and codeql/ side by side.
func QueryPackDir(knowledgeRoot string) string {
	return filepath.Join(filepath.Dir(knowledgeRoot), "codeql", indexQueryPackSubdir, "cpp")
}

// Run builds the whole-repo program index and writes it to
// 01_context/repo_facts.v1.json.
//
// Two error classes, deliberately distinguished.
//
// A repository CodeQL cannot extract, or a query that will not run, is a
// DEGRADATION: the artifact is still written, with the affected capabilities
// "unavailable" and a note naming the cause, and Run returns nil. The
// alternative — no artifact — makes every downstream negative result
// unreadable, because "no callers found" and "no index existed" look
// identical to a consumer that has nothing to check.
//
// A schema violation or an unwritable artifact is a PIPELINE ERROR and
// returns non-nil. Swallowing those would let the run continue against a
// contract nobody upheld, and the stages after this one would read a file
// whose shape they were promised and did not get.
func Run(cfg config.Config, db codedb.DatabaseProvider, eng TableQuerier) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1,
		RunID:         manifest.RunID,
		Scope:         manifest.Scope,
		Languages:     []string{lang},
		// Build reachability is never computed: the database is built with
		// --build-mode=none, so nothing here can say whether a path is
		// reachable under any particular build configuration.
		Capabilities: artifacts.IndexCapabilities{
			Symbols:           artifacts.CapabilityUnavailable,
			DirectCalls:       artifacts.CapabilityUnavailable,
			FieldAccesses:     artifacts.CapabilityUnavailable,
			BuildReachability: artifacts.CapabilityUnavailable,
		},
	}

	dbPath, note := ensureDatabase(context.Background(), db, cfg.RunDir, manifest)
	if note != "" {
		facts.IndexNote = note
		return write(cfg.RunDir, facts)
	}

	packDir := QueryPackDir(cfg.KnowledgeRoot)
	query := func(name string) ([][]string, error) {
		if eng == nil {
			return nil, fmt.Errorf("no query engine")
		}
		return eng.QueryTable(context.Background(), codeql.QueryTableOptions{
			DBPath:    dbPath,
			QueryFile: filepath.Join(packDir, name),
		})
	}

	symbolRows, err := query(querySymbols)
	if err != nil {
		facts.IndexNote = querySymbols + ": " + err.Error()
		return write(cfg.RunDir, facts)
	}
	facts.Symbols = decodeSymbols(symbolRows)
	if len(facts.Symbols) == 0 {
		facts.IndexNote = "symbol query returned no indexed definitions; source coverage is partial"
		return write(cfg.RunDir, facts)
	}
	facts.Capabilities.Symbols = artifacts.CapabilityAvailable

	// Each remaining query degrades only its own capability. A field-access
	// query that fails does not make the symbol table untrue, and reporting
	// the whole index as unavailable would throw away work that is sound.
	var notes []string

	edgeRows, err := query(queryCallEdges)
	if err != nil {
		notes = append(notes, queryCallEdges+": "+err.Error())
	} else {
		facts.CallEdges = decodeCallEdges(edgeRows)
		facts.Capabilities.DirectCalls = artifacts.CapabilityAvailable
	}

	if unresolvedRows, uerr := query(queryUnresolved); uerr != nil {
		notes = append(notes, queryUnresolved+": "+uerr.Error())
		// Without the unresolved list the call graph's own gaps are unknown,
		// so no caller list can be read as complete however many edges it
		// holds. Downgrade only from available: a call graph that was never
		// built is unavailable, and calling that "partial" would tell a
		// consumer a partial graph exists when none does.
		if facts.Capabilities.DirectCalls == artifacts.CapabilityAvailable {
			facts.Capabilities.DirectCalls = artifacts.CapabilityPartial
		}
	} else {
		facts.UnresolvedCallSites = decodeUnresolvedCalls(unresolvedRows)
		if len(facts.UnresolvedCallSites) > 0 &&
			facts.Capabilities.DirectCalls == artifacts.CapabilityAvailable {
			facts.Capabilities.DirectCalls = artifacts.CapabilityPartial
		}
	}

	// The counts are the index's own coverage accounting, and they are only
	// meaningful alongside a call graph. Writing them while the call
	// capability is unavailable would hand a consumer a precise-looking
	// total for a graph that was never built.
	if countRows, cerr := query(queryCallSiteCounts); cerr != nil {
		notes = append(notes, queryCallSiteCounts+": "+cerr.Error())
		facts.Capabilities.DirectCalls = artifacts.CapabilityUnavailable
	} else if counts, derr := decodeCallSiteCounts(countRows); derr != nil {
		notes = append(notes, queryCallSiteCounts+": "+derr.Error())
		facts.Capabilities.DirectCalls = artifacts.CapabilityUnavailable
	} else {
		facts.TotalCallSites = counts.Total
		facts.ResolvedCallSites = counts.Resolved
		facts.UnresolvedCallSiteCount = counts.Unresolved
		facts.ExternalCallSites = counts.External
		facts.AmbiguousCallSites = counts.Ambiguous
	}
	if facts.Capabilities.DirectCalls == artifacts.CapabilityUnavailable {
		// No usable call accounting: drop whatever edges were collected
		// rather than shipping a graph whose gaps cannot be stated.
		facts.CallEdges = nil
		facts.UnresolvedCallSites = nil
		facts.TotalCallSites, facts.ResolvedCallSites = 0, 0
		facts.UnresolvedCallSiteCount, facts.ExternalCallSites, facts.AmbiguousCallSites = 0, 0, 0
	}

	if accessRows, aerr := query(queryFieldAccesses); aerr != nil {
		notes = append(notes, queryFieldAccesses+": "+aerr.Error())
		facts.Capsules = buildCapsules(facts.Symbols, facts.CallEdges, nil)
	} else {
		facts.Capsules = buildCapsules(facts.Symbols, facts.CallEdges, decodeFieldAccesses(accessRows))
		// Never "available". Direct-write detection has a structural gap:
		// a field filled by memcpy, through a pointer alias, or by a
		// designated initializer is absent from direct_field_writes, and
		// calling that complete would invite reading an absent write as
		// proof a field is never written.
		facts.Capabilities.FieldAccesses = artifacts.CapabilityPartial
	}

	facts.IndexNote = joinNotes(notes)
	return write(cfg.RunDir, facts)
}

// ensureDatabase returns the database path, or a note explaining why there
// is none. A missing provider is not a crash: the run continues without an
// index and says so.
func ensureDatabase(ctx context.Context, db codedb.DatabaseProvider, runDir string, manifest artifacts.Manifest) (string, string) {
	if db == nil {
		return "", "no database provider configured for this run"
	}
	if manifest.RepoURL == "" || manifest.Commit == "" {
		return "", "no pinned repository@commit; the program index needs one to build a database"
	}
	dbPath, err := db.Ensure(ctx, codedb.Scope{
		RunDir: runDir, Repository: manifest.RepoURL, Commit: manifest.Commit,
	})
	if err != nil {
		return "", "codeql database: " + err.Error()
	}
	return dbPath, ""
}

func joinNotes(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	out := notes[0]
	for _, n := range notes[1:] {
		out += "; " + n
	}
	return out
}

// write validates the artifact against its own schema before persisting it.
// The Go struct and the schema are two definitions of one contract, and a
// stage that writes a file the next stage cannot parse has not degraded, it
// has broken.
func write(runDir string, facts artifacts.RepoFacts) error {
	if facts.Capabilities.Symbols == artifacts.CapabilityUnavailable || len(facts.Capsules) == 0 {
		facts.CoverageStatus = artifacts.CapabilityPartial
	}
	data, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("marshal repo facts: %w", err)
	}
	if err := schema.Validate(schema.RepoFactsV1, data); err != nil {
		return fmt.Errorf("repo facts failed schema validation: %w", err)
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		return fmt.Errorf("write repo facts: %w", err)
	}
	if facts.CoverageStatus == artifacts.CapabilityPartial {
		manifest, err := runfs.LoadManifest(runDir)
		if err != nil {
			return err
		}
		manifest.CoverageStatus = artifacts.CapabilityPartial
		if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
			return err
		}
	}
	return nil
}
