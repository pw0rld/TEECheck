package runfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func ManifestPath(runDir string) string {
	return filepath.Join(runDir, "00_manifest.json")
}

func ProjectProfilePath(runDir string) string {
	return filepath.Join(runDir, "01_profile", "project_profile.json")
}

func RepoMapPath(runDir string) string {
	return filepath.Join(runDir, "01_repo_map", "repo_map.json")
}

func HotspotIndexPath(runDir string) string {
	return filepath.Join(runDir, "02_hotspots", "hotspot_index.json")
}

func CasePacksDir(runDir string) string {
	return filepath.Join(runDir, "03_cases")
}

func ExpertDir(runDir string) string {
	return filepath.Join(runDir, "04_expert")
}

func ChallengerDir(runDir string) string {
	return filepath.Join(runDir, "05_challenger")
}

func VerifierDir(runDir string) string {
	return filepath.Join(runDir, "06_verifier")
}

func ArbiterDir(runDir string) string {
	return filepath.Join(runDir, "07_arbiter")
}

func ArbiterPacketsDir(runDir string) string {
	return filepath.Join(runDir, "07_arbiter", "packets")
}

func ArbiterFindingsPath(runDir string) string {
	return filepath.Join(runDir, "07_arbiter", "findings.json")
}

func ReviewDir(runDir string) string {
	return filepath.Join(runDir, "08_review")
}

func ReviewRecordsPath(runDir string) string {
	return filepath.Join(runDir, "08_review", "review_records.jsonl")
}

func CuratorDir(runDir string) string {
	return filepath.Join(runDir, "09_curator")
}

func LoadManifest(runDir string) (artifacts.Manifest, error) {
	var manifest artifacts.Manifest
	if err := ReadJSON(ManifestPath(runDir), &manifest); err != nil {
		return artifacts.Manifest{}, err
	}
	return manifest, nil
}

func ReadJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return ReadJSONFromBytes(data, out)
}

func ReadJSONFromBytes(data []byte, out any) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse json: %w", err)
	}
	return nil
}

func WriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func WriteText(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
