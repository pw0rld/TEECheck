package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/taint"
)

const prescanContextSchema = "teecheck.taint_prescan_context.v1"

type prescanContextSnapshot struct {
	SchemaVersion string                   `json:"schema_version"`
	Context       *planner.PreScannedTaint `json:"context"`
}

func prescanContextPath(runDir string) string {
	return filepath.Join(runfs.ContextDir(runDir), "taint_prescan.json")
}

// runEntryTaintPrescan is L2 navigation work. It neither promotes cases nor
// charges a Planner round/query, and it never builds another database.
// The result is retained for every sample and for process recovery.
func runEntryTaintPrescan(cfg config.Config, eng taint.Engine, db codedb.DatabaseProvider, runDir, srcRoot string) *planner.PreScannedTaint {
	contextForPlanner := &planner.PreScannedTaint{}
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps, "Entry taint prescan unavailable: cannot read the scan manifest: "+err.Error())
	} else {
		var facts artifacts.RepoFacts
		var factsPtr *artifacts.RepoFacts
		if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err == nil {
			factsPtr = &facts
		} else {
			contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps, "Entry taint prescan has no readable symbol index; endpoint names may be incomplete.")
		}
		out, scanErr := taint.RunPrescan(context.Background(), eng, db, taint.PrescanRequest{
			RunDir: runDir, RepoRoot: srcRoot, Repository: manifest.RepoURL, Commit: manifest.Commit,
			QueryPath: filepath.Join(filepath.Dir(cfg.KnowledgeRoot), "codeql", "trustir", "cpp", "flow", "EntrySurfaceToSink.ql"),
			Facts:     factsPtr,
		})
		contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps, out.CoverageGaps...)
		if scanErr != nil {
			contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps, "Entry taint prescan did not complete: "+scanErr.Error())
		}
		if out.Fact.Status == "success" && out.FactRef != "" {
			contextForPlanner.FactRef, contextForPlanner.Summary = out.FactRef, out.Summary
			contextForPlanner.ContentSHA256 = out.Fact.ContentSHA256
		} else {
			status := out.Fact.Status
			if status == "" {
				status = "unresolved"
			}
			contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps,
				fmt.Sprintf("Entry taint prescan status=%s; no pre-scanned paths were supplied (fact_ref=%s). This is not a safety conclusion.", status, out.FactRef))
		}
	}
	if err := writeResumeJSON(prescanContextPath(runDir), prescanContextSnapshot{SchemaVersion: prescanContextSchema, Context: contextForPlanner}); err != nil {
		// A prescan failure must leave the ordinary Planner available. A later
		// resume will fail closed if its required context was not persisted.
		contextForPlanner.CoverageGaps = append(contextForPlanner.CoverageGaps, "Entry taint prescan context could not be persisted: "+err.Error())
	}
	return contextForPlanner
}

func loadPrescanContext(runDir string) (*planner.PreScannedTaint, error) {
	f, err := os.Open(prescanContextPath(runDir))
	if os.IsNotExist(err) {
		return nil, nil // Older runs and direct Planner test seams have no L2 snapshot.
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	var saved prescanContextSnapshot
	if err := decoder.Decode(&saved); err != nil {
		return nil, fmt.Errorf("decode prescan context: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("prescan context must contain one JSON object")
	}
	if saved.SchemaVersion != prescanContextSchema || saved.Context == nil {
		return nil, fmt.Errorf("invalid prescan context schema")
	}
	return saved.Context, nil
}
