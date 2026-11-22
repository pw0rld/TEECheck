package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

const checkpointVersion = "teecheck.planner_checkpoint.v1"

// Checkpoint is the last committed planner round and its resumable runtime.
// Journal prefixes bind state to the facts it actually observed. Any later
// partial round is discarded on recovery, while its spent budget is retained.
type Checkpoint struct {
	SchemaVersion        string                              `json:"schema_version"`
	RunID                string                              `json:"run_id"`
	SampleIndex          int                                 `json:"sample_index"`
	Profile              PromptProfile                       `json:"profile"`
	ConfigSHA256         string                              `json:"config_sha256"`
	ExecutableSHA256     string                              `json:"executable_sha256"`
	TreeContentHash      string                              `json:"tree_content_hash"`
	ObservedFileHashes   map[string]string                   `json:"observed_file_hashes"`
	LastCommittedRound   int                                 `json:"last_committed_round"`
	State                *PlannerState                       `json:"state"`
	Recon                reconSnapshot                       `json:"recon"`
	Budget               Budget                              `json:"budget"`
	ElapsedNanos         int64                               `json:"elapsed_nanos"`
	ObservedPaths        map[string]bool                     `json:"observed_paths"`
	Observations         map[string]bool                     `json:"observations"`
	Loop                 loopSnapshot                        `json:"loop"`
	Leads                []artifacts.AuditLead               `json:"leads"`
	ExecutedToolFactRefs []string                            `json:"executed_tool_fact_refs"`
	CoverageGaps         []string                            `json:"coverage_gaps"`
	RunErrors            []artifacts.RoundError              `json:"run_errors"`
	DonePayload          actions.DonePayload                 `json:"done_payload"`
	DoneAccepted         bool                                `json:"done_accepted"`
	ClosingContracts     map[int][]artifacts.CaseInvariantV2 `json:"closing_contracts"`
	TerminationReason    string                              `json:"termination_reason"`
	AvoidPaths           []string                            `json:"avoid_paths"`
	Journals             map[string]JournalBoundary          `json:"journals"`
	EventOffset          int64                               `json:"event_offset"`
	InFlight             *pendingLLM                         `json:"in_flight,omitempty"`
	InterruptedRound     bool                                `json:"interrupted_round,omitempty"`
	Completed            bool                                `json:"completed"`
	CachedResult         *CheckpointResult                   `json:"cached_result,omitempty"`
	runDir               string
}

type JournalBoundary struct {
	Offset int64  `json:"offset"`
	SHA256 string `json:"sha256"`
}

type CheckpointResult struct {
	Bundle         *artifacts.EvidenceBundle    `json:"bundle"`
	Investigations []artifacts.TWEInvestigation `json:"investigations"`
	CasePacks      []artifacts.CasePack         `json:"case_packs"`
}

func (r *CheckpointResult) RunResult() RunResult {
	return RunResult{Bundle: r.Bundle, Investigations: r.Investigations, CasePacks: r.CasePacks}
}

type pendingLLM struct {
	ReservedTokens int  `json:"reserved_tokens"`
	Recon          bool `json:"recon"`
}
type loopSnapshot struct {
	Action string `json:"action"`
	Args   string `json:"args"`
	Count  int    `json:"count"`
}
type readRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
type reconSnapshot struct {
	Mode                                                  ReconMode
	Phase                                                 string
	ModulesTotal, FunctionsTotal, FilesTotal              int
	RepositoryCardRead, RootListed                        bool
	RelationQueries                                       int
	ModulesViewed, SymbolsViewed, SymbolSpread, FilesRead map[string]bool
	LinesRead                                             map[string][]readRange
	EntryCapability                                       string
	EntrySurfaces                                         map[artifacts.SymbolID]artifacts.EntrySurface
	EntryLinesRead                                        map[string]map[int]bool
	BudgetExhausted, Skipped                              bool
	LeadsOpened                                           int
}

func snapshotRecon(r *ReconState) reconSnapshot {
	lines := make(map[string][]readRange, len(r.linesRead))
	for p, ranges := range r.linesRead {
		for _, v := range ranges {
			lines[p] = append(lines[p], readRange{v.start, v.end})
		}
	}
	return reconSnapshot{r.Mode, r.phase, r.modulesTotal, r.functionsTotal, r.filesTotal, r.repositoryCardRead, r.rootListed, r.relationQueries, r.modulesViewed, r.symbolsViewed, r.symbolSpread, r.filesRead, lines, r.entryCapability, r.entrySurfaces, r.entryLinesRead, r.budgetExhausted, r.skipped, r.leadsOpened}
}
func (s reconSnapshot) restore() *ReconState {
	r := NewReconState(s.Mode)
	r.phase = s.Phase
	r.modulesTotal = s.ModulesTotal
	r.functionsTotal = s.FunctionsTotal
	r.filesTotal = s.FilesTotal
	r.repositoryCardRead = s.RepositoryCardRead
	r.rootListed = s.RootListed
	r.relationQueries = s.RelationQueries
	r.modulesViewed = s.ModulesViewed
	r.symbolsViewed = s.SymbolsViewed
	r.symbolSpread = s.SymbolSpread
	r.filesRead = s.FilesRead
	for p, ranges := range s.LinesRead {
		for _, v := range ranges {
			r.linesRead[p] = append(r.linesRead[p], lineRange{v.Start, v.End})
		}
	}
	r.entryCapability = s.EntryCapability
	r.entrySurfaces = s.EntrySurfaces
	r.entryLinesRead = s.EntryLinesRead
	r.budgetExhausted = s.BudgetExhausted
	r.skipped = s.Skipped
	r.leadsOpened = s.LeadsOpened
	return r
}

// CheckpointPath is the atomic planner state file shared by all samples.
func CheckpointPath(runDir string) string {
	return filepath.Join(runfs.PlannerDir(runDir), "state.json")
}

// InspectCheckpoint validates source contents and committed journal prefixes
// without modifying anything. Call before opening a resumed event recorder.
func InspectCheckpoint(runDir, repoRoot string) (*Checkpoint, error) {
	f, err := os.Open(CheckpointPath(runDir))
	if err != nil {
		return nil, fmt.Errorf("resume checkpoint: %w", err)
	}
	defer f.Close()
	var cp Checkpoint
	if err = json.NewDecoder(io.LimitReader(f, 64<<20)).Decode(&cp); err != nil {
		return nil, fmt.Errorf("decode resume checkpoint: %w", err)
	}
	cp.runDir = runDir
	if cp.SchemaVersion != checkpointVersion || cp.State == nil || cp.RunID == "" || cp.State.RunID != cp.RunID {
		return nil, fmt.Errorf("invalid planner checkpoint identity/version")
	}
	if cp.TerminationReason == "policy_refusal" {
		return nil, fmt.Errorf("cannot resume a terminal upstream policy refusal")
	}
	tree, err := sourcehash.TreeExcluding(repoRoot, []string{runDir})
	if err != nil {
		return nil, fmt.Errorf("resume source tree: %w", err)
	}
	if tree != cp.TreeContentHash {
		return nil, fmt.Errorf("resume source tree content changed")
	}
	var paths []string
	for p := range cp.ObservedFileHashes {
		paths = append(paths, p)
	}
	hashes, err := sourcehash.Files(repoRoot, paths)
	if err != nil {
		return nil, fmt.Errorf("resume observed source: %w", err)
	}
	if !reflect.DeepEqual(hashes, cp.ObservedFileHashes) {
		return nil, fmt.Errorf("resume observed source content changed")
	}
	if err = validateJournalBoundaries(&cp); err != nil {
		return nil, err
	}
	executable, err := executableHash()
	if err != nil {
		return nil, err
	}
	if cp.ExecutableSHA256 != executable {
		return nil, fmt.Errorf("resume scanner executable changed")
	}
	return &cp, nil
}

// RestoreCheckpointJournals removes uncommitted suffixes. The caller can
// archive those suffixes first. All prefixes are validated before any write.
func RestoreCheckpointJournals(cp *Checkpoint) error {
	if cp == nil || cp.runDir == "" {
		return fmt.Errorf("checkpoint was not inspected")
	}
	if err := validateJournalBoundaries(cp); err != nil {
		return err
	}
	for _, name := range checkpointJournalNames {
		boundary, ok := cp.Journals[name]
		if !ok {
			return fmt.Errorf("checkpoint lacks journal %s", name)
		}
		path := filepath.Join(cp.runDir, filepath.FromSlash(name))
		info, err := os.Stat(path)
		if os.IsNotExist(err) && boundary.Offset == 0 {
			continue
		}
		if err != nil {
			return err
		}
		if info.Size() == boundary.Offset {
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		err = f.Truncate(boundary.Offset)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

var checkpointJournalNames = []string{"04_planner/rounds.jsonl", "04_planner/audit_leads.jsonl", "events.jsonl"}

func validateJournalBoundaries(cp *Checkpoint) error {
	for _, name := range checkpointJournalNames {
		boundary, ok := cp.Journals[name]
		if !ok || boundary.Offset < 0 {
			return fmt.Errorf("invalid checkpoint journal %s", name)
		}
		actual, err := journalBoundary(filepath.Join(cp.runDir, filepath.FromSlash(name)), boundary.Offset)
		if err != nil {
			return fmt.Errorf("resume journal %s: %w", name, err)
		}
		if actual.SHA256 != boundary.SHA256 {
			return fmt.Errorf("resume journal prefix changed: %s", name)
		}
	}
	return nil
}

// limit < 0 snapshots the whole current journal; otherwise exactly that prefix.
func journalBoundary(path string, limit int64) (JournalBoundary, error) {
	h := sha256.New()
	f, err := os.Open(path)
	if os.IsNotExist(err) && (limit <= 0) {
		return JournalBoundary{0, hex.EncodeToString(h.Sum(nil))}, nil
	}
	if err != nil {
		return JournalBoundary{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return JournalBoundary{}, err
	}
	if limit < 0 {
		limit = info.Size()
	}
	if info.Size() < limit {
		return JournalBoundary{}, fmt.Errorf("journal shorter than committed offset")
	}
	if _, err = io.CopyN(h, f, limit); err != nil {
		return JournalBoundary{}, err
	}
	return JournalBoundary{limit, hex.EncodeToString(h.Sum(nil))}, nil
}
func executableHash() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func checkpointConfigHash(cfg RunConfig) string {
	b := cfg.Budget
	b.startedAt = time.Time{}
	b.RoundsUsed = 0
	b.ReconRoundsUsed = 0
	b.TokensUsed = 0
	b.ReconTokensUsed = 0
	b.InvestigationTokensUsed = 0
	b.TaintQueriesUsed = 0
	data, _ := json.Marshal(struct {
		Profile         PromptProfile
		Budget          Budget
		Model           string
		MaxOutputTokens int
		ReasoningEffort string
		Temperature     float64
		MaxActions      int
		AvoidPaths      []string
		TWE             string
	}{cfg.Profile, b, cfg.Model, cfg.MaxOutputTokens, cfg.ReasoningEffort, cfg.Temperature, cfg.MaxActionsPerRound, cfg.AvoidPaths, cfg.TWEContext})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func writeCheckpoint(cp *Checkpoint) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := runfs.PlannerDir(cp.runDir)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, CheckpointPath(cp.runDir)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func cloneCheckpoint(cp *Checkpoint) (*Checkpoint, error) {
	data, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var copy Checkpoint
	if err = json.Unmarshal(data, &copy); err != nil {
		return nil, err
	}
	copy.runDir = cp.runDir
	return &copy, nil
}

// checkpointHeartbeat records active time while a provider/query blocks. It
// snapshots an immutable reservation; stopping waits for its writer before the
// main goroutine replaces the checkpoint with completed usage. Downtime is
// therefore excluded, with at most one tick of active time lost on a hard kill.
func checkpointHeartbeat(runDir string) func() error {
	data, err := os.ReadFile(CheckpointPath(runDir))
	if err != nil {
		return func() error { return err }
	}
	var cp Checkpoint
	if err = json.Unmarshal(data, &cp); err != nil {
		return func() error { return err }
	}
	cp.runDir = runDir
	start := time.Now()
	elapsed := cp.ElapsedNanos
	done := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var lastErr error
		for {
			select {
			case <-done:
				finished <- lastErr
				return
			case <-ticker.C:
				cp.ElapsedNanos = elapsed + time.Since(start).Nanoseconds()
				if err := writeCheckpoint(&cp); err != nil {
					lastErr = err
				}
			}
		}
	}()
	return func() error { close(done); return <-finished }
}
