package runinit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

var nonAlnumPattern = regexp.MustCompile(`[^a-z0-9]+`)

func Run(cfg config.Config, now time.Time) (string, error) {
	runID := strings.TrimSpace(cfg.RunID)
	if runID == "" {
		runID = defaultRunID(cfg, now)
	}

	runRoot := filepath.Join(cfg.OutputDir, runID)
	stageDirs := []string{
		filepath.Join(runRoot, "01_profile"),
		filepath.Join(runRoot, "01_repo_map"),
		filepath.Join(runRoot, "02_hotspots"),
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

	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         runID,
		RepoURL:       cfg.RepoURL,
		LocalPath:     cfg.LocalPath,
		Commit:        cfg.Commit,
		Focus:         cfg.Focus,
		CreatedAt:     now.Format(time.RFC3339),
		ToolVersions: map[string]string{
			"teecheck": "harness-prototype",
			"go":       "1.25.0",
		},
	}

	manifestPath := filepath.Join(runRoot, "00_manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	return runRoot, nil
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
