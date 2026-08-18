package runinit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

var nonAlnumPattern = regexp.MustCompile(`[^a-z0-9]+`)

func Run(cfg config.Config, now time.Time) (string, error) {
	cfg = cfg.WithLLMProviderDefaults()
	runID := strings.TrimSpace(cfg.RunID)
	if runID == "" {
		runID = defaultRunID(cfg, now)
	}

	runRoot := filepath.Join(cfg.OutputDir, runID)
	stageDirs := []string{
		filepath.Join(runRoot, "01_profile"),
		filepath.Join(runRoot, "03_cases"),
		filepath.Join(runRoot, "04_expert"),
		filepath.Join(runRoot, "05_challenger"),
		filepath.Join(runRoot, "06_verifier"),
		filepath.Join(runRoot, "07_arbiter", "packets"),
	}

	for _, dir := range stageDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create run directory %s: %w", dir, err)
		}
	}

	build := currentBuildProvenance()
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         runID,
		RepoURL:       cfg.RepoURL,
		LocalPath:     cfg.LocalPath,
		Commit:        cfg.Commit,
		Focus:         cfg.Focus,
		Hint:          cfg.Hint,
		CreatedAt:     now.Format(time.RFC3339),
		ToolVersions: map[string]string{
			"teecheck": build.Version,
			"go":       build.GoVersion,
		},
		Build: &build,
		Configuration: &artifacts.RunConfiguration{
			Command:         cfg.Command,
			Mode:            cfg.Mode,
			Samples:         cfg.Samples,
			MaxCases:        cfg.MaxCases,
			MaxHotspots:     cfg.MaxHotspots,
			MaxDialogRounds: cfg.MaxDialogRounds,
			StaticTools:     cfg.StaticTools,
			LLM: artifacts.LLMConfiguration{
				Provider:        cfg.LLMProvider,
				BaseURL:         cfg.LLMBaseURL,
				Model:           cfg.LLMModel,
				Transport:       cfg.LLMTransport,
				ReasoningEffort: cfg.LLMReasoningEffort,
				TimeoutSeconds:  cfg.LLMTimeoutSec,
				MaxOutputTokens: cfg.LLMMaxTokens,
				Temperature:     cfg.LLMTemp,
				APIKeyPresent:   cfg.LLMAPIKey != "",
			},
		},
	}

	manifestPath := filepath.Join(runRoot, "00_manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	return runRoot, nil
}

func currentBuildProvenance() artifacts.BuildProvenance {
	build := artifacts.BuildProvenance{
		Version:   "unknown",
		GoVersion: runtime.Version(),
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return build
	}
	if strings.TrimSpace(info.Main.Version) != "" {
		build.Version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			build.VCSRevision = setting.Value
		case "vcs.modified":
			build.VCSModified = setting.Value == "true"
		}
	}
	return build
}

// RecordPlannerLimits adds the planner controls after pipeline construction,
// where the planner package's resolved defaults are known.
func RecordPlannerLimits(runDir string, limits artifacts.PlannerLimits) error {
	path := filepath.Join(runDir, "00_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest artifacts.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.Configuration == nil {
		manifest.Configuration = &artifacts.RunConfiguration{}
	}
	manifest.Configuration.Planner = &limits
	if err := writeJSON(path, manifest); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

// RecordToolVersion adds one resolved tool version or explicit status to the
// manifest after the pipeline has constructed the tool that will be used.
func RecordToolVersion(runDir, name, version string) error {
	path := filepath.Join(runDir, "00_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest artifacts.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.ToolVersions == nil {
		manifest.ToolVersions = make(map[string]string)
	}
	manifest.ToolVersions[name] = version
	if err := writeJSON(path, manifest); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func defaultRunID(cfg config.Config, now time.Time) string {
	repoPart := sanitizeStem(filepath.Base(cfg.LocalPath))
	focusPart := sanitizeStem(cfg.Focus)
	if repoPart == "" {
		repoPart = "repo"
	}
	if focusPart == "" {
		focusPart = "focus"
	}
	return fmt.Sprintf("%s-%s-%s", now.Format("2006-01-02-150405"), repoPart, focusPart)
}

func sanitizeStem(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = nonAlnumPattern.ReplaceAllString(value, "-")
	return strings.Trim(value, "-")
}
