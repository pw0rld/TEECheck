package codeql

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// codeqlCreateTimeout and codeqlAnalyzeTimeout bound calls that previously
// had no bound of their own beyond the caller's context, which on the
// fact-layer path is context.Background(). Both are set from what CodeQL
// actually costs rather than from what is convenient: extracting a large
// C/C++ tree under --build-mode=none is tens of minutes, and a query run
// over that database is minutes. They exist to stop a wedged CodeQL from
// holding a run open forever, not to police a slow one.
const (
	codeqlCreateTimeout  = 2 * time.Hour
	codeqlAnalyzeTimeout = 1 * time.Hour
	codeqlVersionTimeout = 30 * time.Second
)

// codeqlMaxOutputBytes caps the console streams. CodeQL's stdout/stderr
// carry progress and diagnostics only — RESULTS GO TO THE SARIF FILE named
// by --output, which this package reads from disk and which no cap here
// touches. So unlike semgrep, a cut console stream costs a diagnostic, not
// a result. 16 MiB is 4x the executor default, chosen because CodeQL's
// per-query progress output on a large database is verbose enough to blow
// past the default while still being nowhere near this.
//
// A var rather than a const so the truncation path can be exercised in a
// test without generating 16 MiB of output.
var codeqlMaxOutputBytes = 16 << 20

// Engine invokes the CodeQL CLI. The zero value is not usable; construct with
// New or NewWithBin.
type Engine struct {
	// bin is the codeql executable (a name resolved on PATH, or an absolute
	// path to a bundle's codeql).
	bin string

	// Exec is the injection seam: when set, both subprocess calls route
	// through it and leave tool_call_* events. An exported field rather
	// than a third constructor because the two existing constructors
	// already differ only in how bin is resolved, and a
	// NewWithBinAndExecutor would multiply that axis; an Engine is built
	// once per run and configured at the wiring site, so a plain
	// assignment reads better there. Nil means "run codeql, record
	// nothing" — cmd/twescan and the staticcheck adapter build their own
	// engines with no event stream to write to.
	//
	// Adding a field does not disturb trustirfacts.Engine, which this
	// type satisfies structurally by method set.
	Exec executor.Executor
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

// Version returns the CodeQL CLI version reported by the executable used by
// this engine. The probe routes through the same executor as database work so
// provenance collection is visible in the run event stream.
func (e *Engine) Version(ctx context.Context) (string, error) {
	if !e.Available() {
		return "", fmt.Errorf("codeql not available (bin=%q)", e.bin)
	}
	res := e.run(ctx, "codeql-version", []string{"version", "--format=json"}, codeqlVersionTimeout, "")
	if err := res.Err(); err != nil {
		return "", fmt.Errorf("codeql version failed: %w\n%s", err, tail(res.Combined(), 2000))
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(res.Stdout, &payload); err != nil {
		return "", fmt.Errorf("parse codeql version: %w", err)
	}
	if strings.TrimSpace(payload.Version) == "" {
		return "", fmt.Errorf("parse codeql version: response has no version")
	}
	return strings.TrimSpace(payload.Version), nil
}

// CreateDBOptions configures a database build.
type CreateDBOptions struct {
	Language   string // e.g. "rust", "cpp"
	SourceRoot string // repo / crate root to extract
	DBPath     string // output database directory
	Overwrite  bool
	// BuildMode selects how the extractor obtains code, e.g. "none" for C/C++
	// no-compile extraction of a full source tree. Empty uses the extractor
	// default (autobuild, which cargo drives for Rust).
	BuildMode string
	// ExtraPATH is prepended to PATH for the build (e.g. so the Rust
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
	if opts.BuildMode != "" {
		args = append(args, "--build-mode="+opts.BuildMode)
	}
	res := e.run(ctx, "codeql-database-create", args, codeqlCreateTimeout, opts.ExtraPATH)
	if err := res.Err(); err != nil {
		return fmt.Errorf("codeql database create failed: %w\n%s", err, tail(res.Combined(), 2000))
	}
	return nil
}

// run is the single chokepoint both CodeQL invocations go through. The
// Profile is identical for the two: same binary, same environment
// contract, same output semantics — only the logical name and the timeout
// differ, and those are the two parameters.
func (e *Engine) run(ctx context.Context, name string, args []string, timeout time.Duration, extraPATH string) executor.Result {
	return executor.OrLocal(e.Exec).Run(ctx, executor.Request{
		Name:    name,
		Command: e.bin,
		Args:    args,
		Profile: executor.Profile{
			// CodeQL resolves query packs and their dependencies from the
			// GitHub registry, and writes the database directory and the
			// SARIF output file.
			Network:        executor.NetworkAllow,
			Write:          executor.WriteWorkspace,
			Timeout:        timeout,
			MaxOutputBytes: codeqlMaxOutputBytes,
			// Parity: envWithExtraPATH returned nil (inherit everything)
			// when ExtraPATH was empty, and os.Environ() with PATH
			// rewritten when it was not. Both cases inherit the full
			// parent environment; only PATH differs.
			EnvAllowlist: executor.InheritedEnvNames(),
		},
		Env: executor.PrependPATH(extraPATH),
	})
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

	res := e.run(ctx, "codeql-database-analyze", args, codeqlAnalyzeTimeout, opts.ExtraPATH)
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("codeql database analyze failed: %w\n%s", err, tail(res.Combined(), 2000))
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("codeql analyze: read sarif: %w", err)
	}
	return ParseSARIF(data)
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "..." + string(b[len(b)-n:])
}
