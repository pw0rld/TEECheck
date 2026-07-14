package codeql

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Engine invokes the CodeQL CLI. The zero value is not usable; construct with
// New or NewWithBin.
type Engine struct {
	// bin is the codeql executable (a name resolved on PATH, or an absolute
	// path to a bundle's codeql).
	bin string
}

// New returns an Engine that resolves "codeql" on PATH.
func New() *Engine { return &Engine{bin: "codeql"} }

// NewWithBin returns an Engine using an explicit codeql binary path, e.g. a
// bundle install under /root/codeql-home/codeql/codeql.
func NewWithBin(bin string) *Engine {
	if strings.TrimSpace(bin) == "" {
		bin = "codeql"
	}
	return &Engine{bin: bin}
}

// Available reports whether the codeql binary can be found and executed. It is
// the guard the pipeline checks before treating CodeQL as a usable fact
// engine — CodeQL is a hard dependency for TWE verdicts, so an unavailable
// engine must fail loudly upstream, not silently downgrade.
func (e *Engine) Available() bool {
	if e == nil || e.bin == "" {
		return false
	}
	if filepath.IsAbs(e.bin) {
		info, err := os.Stat(e.bin)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(e.bin)
	return err == nil
}

// CreateDBOptions configures a database build.
type CreateDBOptions struct {
	Language   string // e.g. "rust"
	SourceRoot string // repo / crate root to extract
	DBPath     string // output database directory
	Overwrite  bool
	// SearchPath is prepended to PATH for the build (e.g. so the Rust
	// extractor finds cargo). Empty leaves the environment untouched.
	ExtraPATH string
}

// CreateDatabase runs `codeql database create`. For Rust, SourceRoot must be a
// compilable cargo crate and cargo must be reachable (see ExtraPATH).
func (e *Engine) CreateDatabase(ctx context.Context, opts CreateDBOptions) error {
	if !e.Available() {
		return fmt.Errorf("codeql not available (bin=%q)", e.bin)
	}
	if opts.Language == "" || opts.SourceRoot == "" || opts.DBPath == "" {
		return fmt.Errorf("codeql create: language, source root, and db path are required")
	}
	args := []string{
		"database", "create", opts.DBPath,
		"--language=" + opts.Language,
		"--source-root=" + opts.SourceRoot,
	}
	if opts.Overwrite {
		args = append(args, "--overwrite")
	}
	cmd := exec.CommandContext(ctx, e.bin, args...)
	cmd.Env = envWithExtraPATH(opts.ExtraPATH)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("codeql database create failed: %w\n%s", err, tail(out, 2000))
	}
	return nil
}

// AnalyzeOptions configures a query run against a database.
type AnalyzeOptions struct {
	DBPath string // an existing database directory
	// Queries are query files, directories, or suites to run. Paths under a
	// query pack that resolves codeql/rust-all (see AdditionalPacks).
	Queries []string
	// AdditionalPacks is prepended to CodeQL's package search path so custom
	// TWE query packs resolve their dependencies against a local bundle.
	AdditionalPacks []string
	ExtraPATH       string
}

// Analyze runs `codeql database analyze` to a temporary SARIF file, parses it,
// and returns the flattened results. The SARIF file is removed before return.
func (e *Engine) Analyze(ctx context.Context, opts AnalyzeOptions) ([]Result, error) {
	if !e.Available() {
		return nil, fmt.Errorf("codeql not available (bin=%q)", e.bin)
	}
	if opts.DBPath == "" || len(opts.Queries) == 0 {
		return nil, fmt.Errorf("codeql analyze: db path and at least one query are required")
	}
	sarifFile, err := os.CreateTemp("", "teecheck-*.sarif")
	if err != nil {
		return nil, fmt.Errorf("codeql analyze: temp sarif: %w", err)
	}
	sarifPath := sarifFile.Name()
	sarifFile.Close()
	defer os.Remove(sarifPath)

	args := []string{
		"database", "analyze", opts.DBPath,
		"--format=sarifv2.1.0",
		"--output=" + sarifPath,
		"--rerun",
	}
	if len(opts.AdditionalPacks) > 0 {
		args = append(args, "--additional-packs="+strings.Join(opts.AdditionalPacks, string(os.PathListSeparator)))
	}
	args = append(args, opts.Queries...)

	cmd := exec.CommandContext(ctx, e.bin, args...)
	cmd.Env = envWithExtraPATH(opts.ExtraPATH)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("codeql database analyze failed: %w\n%s", err, tail(out, 2000))
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("codeql analyze: read sarif: %w", err)
	}
	return ParseSARIF(data)
}

func envWithExtraPATH(extra string) []string {
	if strings.TrimSpace(extra) == "" {
		return nil // inherit parent environment
	}
	env := os.Environ()
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + extra + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+extra)
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "..." + string(b[len(b)-n:])
}
