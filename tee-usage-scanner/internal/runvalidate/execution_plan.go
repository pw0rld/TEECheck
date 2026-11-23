package runvalidate

import (
	"fmt"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func validateExecutionPlan(runDir string, m artifacts.Manifest, all []events.Event, add func(string, string, string, ...any)) {
	path := runfs.ManifestPath(runDir)
	if m.SourceScopeMode != "pinned_checkout" && m.SourceScopeMode != "local_fallback" {
		add("source_scope_mode", path, "missing or unsupported source_scope_mode %q; legacy results are not validated scan attempts", m.SourceScopeMode)
	}
	if m.SourceScopeMode == "pinned_checkout" && (m.RepoURL == "" || m.Commit == "" || m.Commit == "unknown") {
		add("source_scope_identity", path, "pinned checkout requires a repository and concrete revision")
	}
	if m.Scope.Root != "" && m.LocalPath != "" && filepath.Clean(m.Scope.Root) != filepath.Clean(m.LocalPath) {
		add("source_scope_root", path, "scope root and local_path differ")
	}
	if len(m.ExpectedStages) == 0 {
		add("execution_plan_missing", path, "expected_stages is required for a validated scan attempt")
	}
	expected := map[string]bool{}
	for _, s := range m.ExpectedStages {
		if expected[s] {
			add("execution_plan_duplicate", path, "stage %q occurs more than once", s)
		}
		expected[s] = true
	}
	legacy := false
	prescan := false
	if m.Configuration != nil {
		legacy = m.Configuration.EnableLegacyPrior
		prescan = m.Configuration.EnableTaintPrescan
	} else {
		// Backward compatibility for pre-v2 manifests that explicitly listed taint_prescan.
		prescan = expected["taint_prescan"]
	}
	for _, s := range runfs.ExpectedStagesWithOptions(legacy, prescan) {
		if !expected[s] {
			add("execution_plan_missing_stage", path, "required audit stage %q is absent from expected_stages", s)
		}
	}
	starts, ends := map[string]int{}, map[string]int{}
	runStarts, runEnds := 0, 0
	for _, e := range all {
		switch e.Type {
		case events.TypeStageStarted:
			starts[e.Stage]++
		case events.TypeStageCompleted:
			ends[e.Stage]++
		case events.TypeRunStarted:
			runStarts++
		case events.TypeRunCompleted:
			runEnds++
		}
	}
	if runStarts != 1 || runEnds != 1 {
		add("run_lifecycle", filepath.Join(runDir, "events.jsonl"), "want one run start/completion; got %d/%d", runStarts, runEnds)
	}
	for _, s := range m.ExpectedStages {
		if starts[s] != 1 || ends[s] != 1 {
			add("expected_stage_missing", filepath.Join(runDir, "events.jsonl"), "expected stage %q must start and complete exactly once; got %d/%d", s, starts[s], ends[s])
		}
	}
}

func coverageIssues(runDir string, m artifacts.Manifest) []Issue {
	var issues []Issue
	add := func(code, message string) {
		issues = append(issues, Issue{Code: code, Path: runfs.CoverageLedgerPath(runDir), Message: message})
	}
	var ledger artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(runDir), &ledger); err != nil {
		add("coverage_missing", err.Error())
		return issues
	}
	if ledger.RunID != m.RunID {
		add("coverage_run_id", fmt.Sprintf("coverage run_id %q differs from manifest %q", ledger.RunID, m.RunID))
	}
	if ledger.SchemaVersion != "teecheck.coverage_ledger.v1" {
		add("coverage_schema", "unsupported or missing coverage schema")
	}
	if m.CoverageStatus == artifacts.CapabilityPartial {
		add("partial_index", "the program index reports partial source coverage")
	}
	want := 1
	if m.Configuration != nil && m.Configuration.Samples > 0 {
		want = m.Configuration.Samples
	}
	seen := map[int]bool{}
	for _, s := range ledger.BySample {
		if seen[s.SampleIndex] {
			add("coverage_duplicate_sample", fmt.Sprintf("sample %d is duplicated", s.SampleIndex))
		}
		seen[s.SampleIndex] = true
		if s.ReconStatus != "satisfied" {
			add("recon_incomplete", fmt.Sprintf("sample %d reconnaissance status is %q", s.SampleIndex, s.ReconStatus))
		}
		if entry := s.EntrySurfaces; entry != nil && entry.GateApplies && !entry.Complete {
			add("entry_coverage_incomplete", fmt.Sprintf("sample %d entry source coverage is %d/%d across %d/%d required modules", s.SampleIndex, entry.Read, entry.Required, entry.ModulesRead, entry.ModulesRequired))
		}
		if entry := s.EntrySurfaces; entry != nil && s.LeadsOpened == 0 && entry.Capability != artifacts.CapabilityAvailable {
			add("entry_index_incomplete", fmt.Sprintf("sample %d entry index capability is %q; a zero-lead result does not establish complete entry coverage", s.SampleIndex, entry.Capability))
		}
	}
	for i := 0; i < want; i++ {
		if !seen[i] {
			add("coverage_sample_missing", fmt.Sprintf("sample %d has no reconnaissance record", i))
		}
	}
	return issues
}
