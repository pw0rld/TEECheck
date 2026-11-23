package pipeline

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

// A resume preserves the experiment: model routing, budgets, source and
// knowledge must all match. Credentials are deliberately absent from disk.
type resumeSettings struct {
	Version                                         string `json:"version"`
	Focus                                           string `json:"focus"`
	Hint                                            string `json:"hint"`
	Samples, MaxCases, MaxHotspots, MaxDialogRounds int
	Legacy                                          bool
	TaintPrescan                                    bool `json:"taint_prescan,omitempty"`
	StrictContractExit                              bool `json:"strict_contract_exit,omitempty"`
	StaticTools                                     string
	Budget                                          planner.Budget
	Roles                                           map[string]runinit.RoleLLMSnapshot
	KnowledgeRoot                                   string
	KnowledgeHash                                   string
	CacheDir                                        string
}

func resolvedResumeSettings(cfg config.Config, roles map[string]config.Config) (resumeSettings, error) {
	root, err := filepath.Abs(cfg.KnowledgeRoot)
	if err != nil {
		return resumeSettings{}, err
	}
	digest, err := sourcehash.Tree(root)
	if err != nil {
		return resumeSettings{}, fmt.Errorf("fingerprint knowledge: %w", err)
	}
	s := resumeSettings{Version: "teecheck.resume_settings.v1", Focus: cfg.Focus, Hint: cfg.Hint,
		Samples: cfg.Samples, MaxCases: cfg.MaxCases, MaxHotspots: cfg.MaxHotspots, MaxDialogRounds: cfg.MaxDialogRounds,
		Legacy: cfg.EnableLegacyPrior, TaintPrescan: cfg.EnableTaintPrescan,
		StrictContractExit: !cfg.AllowUncontractedCases,
		StaticTools:        cfg.StaticTools, Budget: configuredPlannerBudget(cfg),
		KnowledgeRoot: root, KnowledgeHash: digest, Roles: map[string]runinit.RoleLLMSnapshot{}}
	if cfg.CodeQLCacheDir != "" {
		s.CacheDir, err = filepath.Abs(cfg.CodeQLCacheDir)
		if err != nil {
			return s, err
		}
	}
	for _, role := range config.LLMRoles {
		c := roles[role]
		s.Roles[role] = runinit.RoleLLMSnapshot{Provider: c.LLMProvider, BaseURL: config.RedactedEndpoint(c.LLMBaseURL),
			Model: c.LLMModel, Transport: c.LLMTransport, ReasoningEffort: c.LLMReasoningEffort,
			TimeoutSeconds: c.LLMTimeoutSec, MaxOutputTokens: c.LLMMaxTokens, Temperature: c.LLMTemp, Stream: c.LLMStream}
	}
	return s, nil
}

func resumeSettingsPath(runDir string) string {
	return filepath.Join(runfs.PlannerDir(runDir), "run_config.json")
}

func recordResumeSettings(runDir string, cfg config.Config, roles map[string]config.Config) error {
	s, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		return err
	}
	return writeResumeJSON(resumeSettingsPath(runDir), s)
}

// inspectResume performs no writes; changed inputs cannot destroy the old run.
func inspectResume(cfg config.Config, roles map[string]config.Config) (config.Config, *planner.Checkpoint, error) {
	if cfg.RunDir == "" {
		cfg.RunDir = cfg.Target
	}
	runDir, err := filepath.Abs(cfg.RunDir)
	if err != nil {
		return cfg, nil, err
	}
	cfg.RunDir = runDir
	m, err := runfs.LoadManifest(runDir)
	if err != nil {
		return cfg, nil, fmt.Errorf("resume manifest: %w", err)
	}
	if (cfg.RunID != "" && cfg.RunID != m.RunID) || (cfg.RepoURL != "" && cfg.RepoURL != m.RepoURL) || (cfg.Commit != "" && cfg.Commit != m.Commit) {
		return cfg, nil, fmt.Errorf("resume repository, commit or run ID differs from original manifest")
	}
	var original resumeSettings
	if err = runfs.ReadJSON(resumeSettingsPath(runDir), &original); err != nil {
		return cfg, nil, fmt.Errorf("resume configuration: %w", err)
	}
	current, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		return cfg, nil, err
	}
	if !reflect.DeepEqual(original, current) {
		return cfg, nil, fmt.Errorf("resume configuration or knowledge changed; repeat the original scan, model, cache and budget settings")
	}
	cp, err := planner.InspectCheckpoint(runDir, m.LocalPath)
	if err != nil {
		return cfg, nil, err
	}
	if cp.RunID != m.RunID || cp.Profile.RepoURL != m.RepoURL || cp.Profile.Commit != m.Commit || cp.SampleIndex < 0 {
		return cfg, nil, fmt.Errorf("resume checkpoint differs from manifest")
	}
	prescan, err := loadPrescanContext(runDir)
	if err != nil {
		return cfg, nil, fmt.Errorf("resume entry taint prescan: %w", err)
	}
	for _, stage := range m.ExpectedStages {
		if stage == "taint_prescan" && prescan == nil {
			return cfg, nil, fmt.Errorf("resume entry taint prescan context is missing")
		}
	}
	if cp.State != nil && !reflect.DeepEqual(cp.State.PreScannedTaint, prescan) {
		return cfg, nil, fmt.Errorf("resume entry taint prescan context differs from checkpoint")
	}
	if prescan != nil && prescan.FactRef != "" {
		fact, err := contracts.LoadToolFact(prescan.FactRef, contracts.BindingContext{RunDir: runDir, RepoRoot: m.LocalPath, Scope: m.Scope})
		if err != nil {
			return cfg, nil, fmt.Errorf("resume entry taint prescan evidence: %w", err)
		}
		if fact.Operation != artifacts.TaintPrescanOperation || fact.Status != "success" || prescan.ContentSHA256 == "" || prescan.ContentSHA256 != fact.ContentSHA256 {
			return cfg, nil, fmt.Errorf("resume entry taint prescan evidence identity changed")
		}
	}
	samples := cfg.Samples
	if samples <= 0 {
		samples = 1
	}
	if cp.SampleIndex >= samples {
		return cfg, nil, fmt.Errorf("resume checkpoint sample exceeds configured passes")
	}
	if _, err = decodeDeterministicPacks(filepath.Join(runfs.PlannerDir(runDir), "deterministic-case-packs.json")); err != nil {
		return cfg, nil, fmt.Errorf("resume deterministic packs: %w", err)
	}
	for pass := 1; pass <= cp.SampleIndex; pass++ {
		result, err := loadPassResult(runDir, pass)
		if err != nil {
			return cfg, nil, fmt.Errorf("resume earlier pass: %w", err)
		}
		if result.Bundle.RunID != m.RunID || result.Bundle.Repo.URL != m.RepoURL || result.Bundle.Repo.Commit != m.Commit {
			return cfg, nil, fmt.Errorf("resume pass %d differs from manifest", pass)
		}
	}
	cfg.RunID, cfg.LocalPath, cfg.RepoURL, cfg.Commit = m.RunID, m.LocalPath, m.RepoURL, m.Commit
	return cfg, cp, nil
}

// Retain superseded outputs as one archive (not discoverable as live findings)
// before rolling back the journals to their committed checkpoint boundaries.
func prepareResumeArtifacts(runDir string, cp *planner.Checkpoint) error {
	history := filepath.Join(runfs.PlannerDir(runDir), "resume-history")
	if err := os.MkdirAll(history, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(history, ".attempt-*.tar")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	tw := tar.NewWriter(f)
	names := []string{"events.jsonl", "04_planner/rounds.jsonl", "04_planner/audit_leads.jsonl", "04_planner/state.json", "03_cases", "04_expert", "05_challenger", "06_verifier", "07_arbiter"}
	for _, name := range names {
		path := filepath.Join(runDir, filepath.FromSlash(name))
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			tw.Close()
			f.Close()
			return err
		}
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("unexpected non-regular resume artifact: %s", p)
			}
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(runDir, p)
			h.Name = filepath.ToSlash(rel)
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, src)
			closeErr := src.Close()
			if err != nil {
				return err
			}
			return closeErr
		})
		if err != nil {
			tw.Close()
			f.Close()
			return err
		}
	}
	if err = tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	archive := filepath.Join(history, fmt.Sprintf("attempt-%d.tar", time.Now().UnixNano()))
	if err = os.Rename(tmp, archive); err != nil {
		return err
	}
	if err = planner.RestoreCheckpointJournals(cp); err != nil {
		return err
	}
	for _, dir := range names[4:] {
		path := filepath.Join(runDir, dir)
		if err = os.RemoveAll(path); err != nil {
			return err
		}
		if err = os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func passResultPath(runDir string, pass int) string {
	return filepath.Join(runfs.PlannerDir(runDir), fmt.Sprintf("pass-%d.result.json", pass))
}

func loadPassResult(runDir string, pass int) (planner.RunResult, error) {
	var snapshot planner.CheckpointResult
	if err := runfs.ReadJSON(passResultPath(runDir, pass), &snapshot); err != nil {
		return planner.RunResult{}, err
	}
	if snapshot.Bundle == nil {
		return planner.RunResult{}, fmt.Errorf("resume pass %d has no bundle", pass)
	}
	return snapshot.RunResult(), nil
}

// Keep this encoding identical to the checkpoint's successful result.
func savePassResult(runDir string, pass int, r planner.RunResult) error {
	return writeResumeJSON(passResultPath(runDir, pass), planner.CheckpointResult{Bundle: r.Bundle, Investigations: r.Investigations, CasePacks: r.CasePacks})
}

func writeResumeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

// decodeDeterministicPacks distinguishes an intentionally empty lane from a
// missing snapshot; a resume must never silently re-run this lane.
func decodeDeterministicPacks(path string) ([]artifacts.CasePack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var packs []artifacts.CasePack
	err = json.Unmarshal(b, &packs)
	return packs, err
}
