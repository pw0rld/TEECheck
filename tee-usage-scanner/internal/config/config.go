package config

import (
	"flag"
	"fmt"
	"path/filepath"
)

type Config struct {
	Command           string
	FixtureDir        string
	ReportPath        string
	ReviewDir         string
	RuleDir           string
	SourcePath        string
	GraphJSONPath     string
	PromptPath        string
	FocusArea         string
	GitNexusSSHTarget string
	GitNexusScript    string
	GitNexusRoot      string
	JoernBin          string
	JoernEndpoint     string
	JoernSSHTarget    string
	JoernWorkspace    string
}

func Parse(args []string) (Config, error) {
	if len(args) == 0 {
		return Config{}, usageError("missing subcommand")
	}

	switch args[0] {
	case "scan":
		return parseScan(args[1:])
	case "kgpack":
		return parseKGPack(args[1:])
	default:
		return Config{}, usageError(fmt.Sprintf("unknown subcommand: %s", args[0]))
	}
}

func parseScan(args []string) (Config, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cfg := Config{
		Command:        "scan",
		FixtureDir:     filepath.Clean("fixtures/optee_param_types"),
		ReportPath:     filepath.Clean("reports/findings.json"),
		ReviewDir:      filepath.Clean("reports/reviews"),
		RuleDir:        filepath.Clean("rules"),
		JoernBin:       "joern",
		JoernEndpoint:  "http://127.0.0.1:8080/query-sync",
		JoernSSHTarget: "",
		JoernWorkspace: "/workspace/tee-usage-scanner",
	}

	fs.StringVar(&cfg.FixtureDir, "fixture-dir", cfg.FixtureDir, "Directory containing evidence package JSON fixtures")
	fs.StringVar(&cfg.ReportPath, "report", cfg.ReportPath, "Path to write the scanner report JSON")
	fs.StringVar(&cfg.ReviewDir, "review-dir", cfg.ReviewDir, "Directory to write review bundles for ambiguous findings")
	fs.StringVar(&cfg.RuleDir, "rule-dir", cfg.RuleDir, "Directory containing rule definition JSON files")
	fs.StringVar(&cfg.SourcePath, "src", "", "Source tree to scan with Joern once the backend is available")
	fs.StringVar(&cfg.JoernBin, "joern-bin", cfg.JoernBin, "Path to the joern executable")
	fs.StringVar(&cfg.JoernEndpoint, "joern-endpoint", cfg.JoernEndpoint, "Joern server query-sync endpoint")
	fs.StringVar(&cfg.JoernSSHTarget, "joern-ssh-target", cfg.JoernSSHTarget, "Optional SSH target used to reach a remote Joern server, for example orb-vscode")
	fs.StringVar(&cfg.JoernWorkspace, "joern-workspace", cfg.JoernWorkspace, "Source root as mounted inside the Joern container or remote host")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func parseKGPack(args []string) (Config, error) {
	fs := flag.NewFlagSet("kgpack", flag.ContinueOnError)
	cfg := Config{
		Command:           "kgpack",
		ReportPath:        filepath.Clean("reports/knowledge-pack.json"),
		PromptPath:        filepath.Clean("reports/knowledge-pack.md"),
		FocusArea:         "tee",
		GitNexusSSHTarget: "",
		GitNexusScript:    filepath.Clean("scripts/gitnexus/export_graph.mjs"),
		GitNexusRoot:      "",
	}

	fs.StringVar(&cfg.GraphJSONPath, "graph-json", "", "Path to a GitNexus graph export JSON file; when omitted, kgpack can create one if --src and --gitnexus-ssh-target are provided")
	fs.StringVar(&cfg.SourcePath, "src", "", "Optional source tree associated with the graph export")
	fs.StringVar(&cfg.ReportPath, "report", cfg.ReportPath, "Path to write the knowledge pack JSON")
	fs.StringVar(&cfg.PromptPath, "prompt", cfg.PromptPath, "Path to write the markdown prompt pack")
	fs.StringVar(&cfg.FocusArea, "focus", cfg.FocusArea, "Audit focus for heuristic compression, for example tee")
	fs.StringVar(&cfg.GitNexusSSHTarget, "gitnexus-ssh-target", cfg.GitNexusSSHTarget, "Optional SSH target for a remote GitNexus host, for example orb-vscode")
	fs.StringVar(&cfg.GitNexusScript, "gitnexus-script", cfg.GitNexusScript, "Path to the GitNexus export helper script visible from the remote host")
	fs.StringVar(&cfg.GitNexusRoot, "gitnexus-root", cfg.GitNexusRoot, "Optional remote GitNexus repository root passed through to the export helper")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.GraphJSONPath == "" && (cfg.SourcePath == "" || cfg.GitNexusSSHTarget == "") {
		return Config{}, fmt.Errorf("kgpack requires --graph-json, or both --src and --gitnexus-ssh-target")
	}

	return cfg, nil
}

func usageError(msg string) error {
	return fmt.Errorf("%s\n\nusage:\n  tee-usage-scanner scan [--fixture-dir DIR] [--report FILE] [--review-dir DIR] [--rule-dir DIR]\n  tee-usage-scanner scan --src PATH [--joern-endpoint URL] [--joern-ssh-target HOST] [--joern-workspace DIR] [--report FILE]\n  tee-usage-scanner kgpack --graph-json FILE [--src PATH] [--focus NAME] [--report FILE] [--prompt FILE]\n  tee-usage-scanner kgpack --src PATH --gitnexus-ssh-target HOST [--graph-json FILE] [--focus NAME] [--report FILE] [--prompt FILE]", msg)
}
