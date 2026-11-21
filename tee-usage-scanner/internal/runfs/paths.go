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

// ChallengerNormalizationsPath is where the Challenger records every
// value it replaced (see artifacts.ChallengerNormalizations). The name
// deliberately does not match the "challenge-*.json" /
// "independent-*.json" globs downstream stages iterate over.
func ChallengerNormalizationsPath(runDir string) string {
	return filepath.Join(ChallengerDir(runDir), "normalizations.json")
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

func GraphDir(runDir string) string {
	return filepath.Join(runDir, "02_graph")
}

func GraphPath(runDir string) string {
	return filepath.Join(runDir, "02_graph", "graph.json")
}

func ScannerDir(runDir string) string {
	return filepath.Join(runDir, "06_scanner")
}

func ReviewerDir(runDir string) string {
	return filepath.Join(runDir, "07_reviewer")
}

func AuditorDir(runDir string) string {
	return filepath.Join(runDir, "08_auditor")
}

func AuditorPacketsDir(runDir string) string {
	return filepath.Join(runDir, "08_auditor", "packets")
}

func AuditorFindingsPath(runDir string) string {
	return filepath.Join(runDir, "08_auditor", "findings.json")
}

func PlannerDir(runDir string) string {
	return filepath.Join(runDir, "04_planner")
}

func EvidenceBundlePath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "evidence_bundle.json")
}

func RoundsLogPath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "rounds.jsonl")
}

// AuditLeadsPath is the run's append-only lead revisions, one JSON object per
// line. The last record for a (run, sample, lead_id) is its current state.
//
// JSONL rather than a JSON array because a lead is appended the moment it
// opens, from a loop that runs once per --samples pass. An array would make
// every pass read, merge and rewrite the whole file, and a pass that died
// mid-write would take the earlier passes' leads with it.
func AuditLeadsPath(runDir string) string {
	return filepath.Join(PlannerDir(runDir), "audit_leads.jsonl")
}

// CoverageLedgerPath is the run's single coverage ledger (§6.5).
//
// One file for the whole run, carrying a per-sample breakdown. Every
// downstream consumer unions the samples, so a file per sample would make
// each of them re-aggregate.
func CoverageLedgerPath(runDir string) string {
	return filepath.Join(PlannerDir(runDir), "coverage_ledger.json")
}

func SinkHitsPath(runDir string) string {
	return filepath.Join(runDir, "04_planner", "sink_hits.json")
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
