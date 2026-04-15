package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/stats"
)

// runStats is a minimal command handler for `teecheck stats`. It
// takes a run dir and optionally a repo root (for hallucination-rate
// computation), aggregates all stage artifacts, and either prints a
// human-readable summary or emits the full JSON on --json.
func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	var repoRoot string
	var asJSON bool
	var writeFile string
	fs.StringVar(&repoRoot, "repo-root", "", "Repository checkout to use for hallucination-rate validation (optional)")
	fs.BoolVar(&asJSON, "json", false, "Emit full stats JSON to stdout instead of human summary")
	fs.StringVar(&writeFile, "write", "", "Write JSON stats to this file in addition to printing summary")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: teecheck stats <run-dir> [--repo-root <path>] [--json] [--write <file>]")
	}
	runDir := fs.Arg(0)

	rs, err := stats.Collect(runDir, repoRoot)
	if err != nil {
		return fmt.Errorf("collect stats: %w", err)
	}

	if writeFile != "" {
		data, err := json.MarshalIndent(rs, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal stats: %w", err)
		}
		if err := os.WriteFile(writeFile, data, 0o644); err != nil {
			return fmt.Errorf("write stats: %w", err)
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rs)
	}

	stats.Print(os.Stdout, rs)
	return nil
}
