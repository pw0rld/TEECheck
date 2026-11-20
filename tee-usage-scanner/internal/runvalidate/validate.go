// Package runvalidate verifies that a run directory is a complete,
// internally consistent evidence bundle before it is scored or reported.
package runvalidate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// Issue is one independently actionable integrity failure.
type Issue struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Report is the deterministic result of validating one run directory.
type Report struct {
	RunDir           string  `json:"run_dir"`
	Valid            bool    `json:"valid"`
	Issues           []Issue `json:"issues"`
	RunID            string  `json:"run_id,omitempty"`
	Repository       string  `json:"repository,omitempty"`
	Commit           string  `json:"commit,omitempty"`
	SourceScopeMode  string  `json:"source_scope_mode,omitempty"`
	CreatedAt        string  `json:"created_at,omitempty"`
	CoverageComplete bool    `json:"coverage_complete"`
	CoverageIssues   []Issue `json:"coverage_issues,omitempty"`
}

// Validate checks the run without invoking tools, models, or the network.
func Validate(runDir string) Report {
	report := Report{RunDir: runDir, Issues: make([]Issue, 0)}
	add := func(code, path, format string, args ...any) {
		report.Issues = append(report.Issues, Issue{
			Code: code, Path: path, Message: fmt.Sprintf(format, args...),
		})
	}

	manifestPath := runfs.ManifestPath(runDir)
	var manifest artifacts.Manifest
	if err := runfs.ReadJSON(manifestPath, &manifest); err != nil {
		add("manifest_read", manifestPath, "%v", err)
	} else if strings.TrimSpace(manifest.RunID) == "" {
		add("manifest_run_id", manifestPath, "run_id is required")
	}

	eventsPath := filepath.Join(runDir, "events.jsonl")
	all, err := readEvents(eventsPath)
	if err != nil {
		add("events_read", eventsPath, "%v", err)
	}
	validateEvents(runDir, manifest.RunID, all, add)
	validateExecutionPlan(runDir, manifest, all, add)
	validateFindings(runDir, manifest.RunID, add)
	validateCaseOutputs(runDir, add)
	validateContracts(runDir, manifest, add)
	report.RunID, report.Repository, report.Commit = manifest.RunID, manifest.RepoURL, manifest.Commit
	report.SourceScopeMode = manifest.SourceScopeMode
	report.CreatedAt = manifest.CreatedAt
	report.CoverageIssues = coverageIssues(runDir, manifest)
	for _, issue := range report.CoverageIssues {
		if issue.Code == "coverage_run_id" || issue.Code == "coverage_schema" {
			report.Issues = append(report.Issues, issue)
		}
	}
	report.CoverageComplete = len(report.CoverageIssues) == 0

	report.Valid = len(report.Issues) == 0
	return report
}

func readEvents(path string) ([]events.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var all []events.Event
	r := bufio.NewReader(f)
	lineNumber := 0
	for {
		line, readErr := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			lineNumber++
			var event events.Event
			if err := json.Unmarshal(line, &event); err != nil {
				return all, fmt.Errorf("line %d: parse event: %w", lineNumber, err)
			}
			all = append(all, event)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return all, readErr
		}
	}
	return all, nil
}

func validateEvents(runDir, runID string, all []events.Event, add func(string, string, string, ...any)) {
	eventsPath := filepath.Join(runDir, "events.jsonl")
	started := make(map[string]int)
	completed := make(map[string]int)
	checkedBlobs := make(map[string]struct{})

	for i, event := range all {
		wantSeq := int64(i + 1)
		if event.Seq != wantSeq {
			add("event_sequence", eventsPath, "event %d has seq %d; want %d", i+1, event.Seq, wantSeq)
		}
		if runID != "" && event.RunID != runID {
			add("event_run_id", eventsPath, "event seq %d has run_id %q; manifest has %q", event.Seq, event.RunID, runID)
		}

		for field, ref := range eventBlobRefs(event) {
			if ref == "" {
				continue
			}
			key := field + "\x00" + ref
			if _, ok := checkedBlobs[key]; ok {
				continue
			}
			checkedBlobs[key] = struct{}{}
			validateBlob(runDir, event.Seq, field, ref, add)
		}

		switch event.Type {
		case events.TypeStageStarted:
			started[event.Stage]++
		case events.TypeStageCompleted:
			completed[event.Stage]++
			if event.Reason != "completed" {
				add("stage_status", eventsPath, "stage %q completed with reason %q", event.Stage, event.Reason)
			} else {
				validateStageArtifacts(runDir, event.Stage, add)
			}
		}
	}

	for _, stage := range sortedKeys(started, completed) {
		count := started[stage]
		if completed[stage] != count {
			add("stage_lifecycle", eventsPath, "stage %q has %d start event(s) and %d completion event(s)", stage, count, completed[stage])
		}
	}

	if len(all) == 0 || all[len(all)-1].Type != events.TypeRunCompleted {
		add("terminal_event", eventsPath, "last event must be run_completed")
		return
	}
	last := all[len(all)-1]
	if last.Reason != "completed" {
		add("terminal_status", eventsPath, "run_completed reason is %q; want completed", last.Reason)
	}
}

func sortedKeys(first, second map[string]int) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	for key := range first {
		seen[key] = struct{}{}
	}
	for key := range second {
		seen[key] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func eventBlobRefs(event events.Event) map[string]string {
	return map[string]string{
		"prompt_blob":        event.PromptBlob,
		"response_blob":      event.ResponseBlob,
		"wire_request_blob":  event.WireRequestBlob,
		"wire_response_blob": event.WireResponseBlob,
		"tool_args_blob":     event.ToolArgsBlob,
		"tool_output_blob":   event.ToolOutputBlob,
		"tool_stderr_blob":   event.ToolStderrBlob,
	}
}

func validateBlob(runDir string, seq int64, field, ref string, add func(string, string, string, ...any)) {
	const prefix = "sha256:"
	if !strings.HasPrefix(ref, prefix) || len(ref) != len(prefix)+64 {
		add("blob_reference", filepath.Join(runDir, "events.jsonl"), "event seq %d field %s has invalid reference %q", seq, field, ref)
		return
	}
	hash := strings.TrimPrefix(ref, prefix)
	if _, err := hex.DecodeString(hash); err != nil {
		add("blob_reference", filepath.Join(runDir, "events.jsonl"), "event seq %d field %s has invalid reference %q", seq, field, ref)
		return
	}
	path := filepath.Join(runDir, "blobs", hash+".txt")
	body, err := os.ReadFile(path)
	if err != nil {
		add("blob_missing", path, "event seq %d field %s: %v", seq, field, err)
		return
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != hash {
		add("blob_hash", path, "event seq %d field %s references %s but content hashes to %s", seq, field, hash, got)
	}
}

func validateFindings(runDir, runID string, add func(string, string, string, ...any)) {
	path := runfs.ArbiterFindingsPath(runDir)
	body, err := os.ReadFile(path)
	if err != nil {
		add("findings_read", path, "%v", err)
		return
	}
	var findings artifacts.Findings
	if err := json.Unmarshal(body, &findings); err != nil {
		add("findings_read", path, "parse JSON: %v", err)
		return
	}
	if err := findings.Validate(); err != nil {
		add("findings_contract", path, "%v", err)
	}
	if err := schema.Validate(schema.FindingsV2, body); err != nil {
		add("findings_schema", path, "%v", err)
	}
	if runID != "" && findings.RunID != runID {
		add("findings_run_id", path, "run_id %q does not match manifest run_id %q", findings.RunID, runID)
	}
}

func validateStageArtifacts(runDir, stage string, add func(string, string, string, ...any)) {
	required := map[string][]string{
		"repo_index":   {runfs.RepoFactsPath(runDir)},
		"project_map":  {runfs.ProjectMapPath(runDir)},
		"architecture": {runfs.ArchitectureModelPath(runDir)},
		"invariants":   {runfs.ProjectInvariantsPath(runDir)},
		"l3_planner":   {runfs.EvidenceBundlePath(runDir), runfs.CoverageLedgerPath(runDir)},
		"cases_enrich": {runfs.CasePacksDir(runDir)},
		"expert":       {runfs.ExpertDir(runDir)},
		"challenger":   {runfs.ChallengerDir(runDir)},
		"verifier":     {runfs.VerifierDir(runDir)},
		"arbiter":      {runfs.ArbiterFindingsPath(runDir)},
	}
	for _, path := range required[stage] {
		if _, err := os.Stat(path); err != nil {
			add("stage_artifact_missing", path, "stage %q completed but required output is unavailable: %v", stage, err)
		}
	}
}
