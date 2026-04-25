package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/stats"
)

// statsArgs is the parsed shape of `teecheck stats` invocation.
type statsArgs struct {
	RunDir    string
	RepoRoot  string
	AsJSON    bool
	WriteFile string
}

// parseStatsArgs handles flags and the single positional run-dir in
// any order. stdlib flag.Parse stops at the first non-flag arg, so
// `teecheck stats <run-dir> --repo-root X` silently dropped the
// flag. Looping Parse over the remainder after each captured
// positional lets flags appear before, after, or interleaved with
// the run-dir.
func parseStatsArgs(args []string) (statsArgs, error) {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	var out statsArgs
	fs.StringVar(&out.RepoRoot, "repo-root", "", "Repository checkout to use for hallucination-rate validation (optional)")
	fs.BoolVar(&out.AsJSON, "json", false, "Emit full stats JSON to stdout instead of human summary")
	fs.StringVar(&out.WriteFile, "write", "", "Write JSON stats to this file in addition to printing summary")

	remaining := args
	for {
		if err := fs.Parse(remaining); err != nil {
			return statsArgs{}, err
		}
		if fs.NArg() == 0 {
			break
		}
		if out.RunDir != "" {
			return statsArgs{}, fmt.Errorf("unexpected extra positional argument: %q", fs.Arg(0))
		}
		out.RunDir = fs.Arg(0)
		remaining = fs.Args()[1:]
		if len(remaining) == 0 {
			break
		}
	}
	if out.RunDir == "" {
		return statsArgs{}, fmt.Errorf("usage: teecheck stats <run-dir> [--repo-root <path>] [--json] [--write <file>]")
	}
	return out, nil
}

// runStats is a minimal command handler for `teecheck stats`. It
// takes a run dir and optionally a repo root (for hallucination-rate
// computation), aggregates all stage artifacts, and either prints a
// human-readable summary or emits the full JSON on --json.
func runStats(args []string) error {
	parsed, err := parseStatsArgs(args)
	if err != nil {
		return err
	}
	runDir := parsed.RunDir
	repoRoot := parsed.RepoRoot
	asJSON := parsed.AsJSON
	writeFile := parsed.WriteFile

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
