package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// semgrepTimeout bounds a scan that previously had no bound of its own —
// only whatever deadline the caller's context happened to carry, which for
// the bus-backed scanner tool is none. 30 minutes is far longer than any
// scan this project runs (the benchmark fixtures finish in seconds) while
// still being short enough that a wedged semgrep cannot hold a run open
// indefinitely.
const semgrepTimeout = 30 * time.Minute

// semgrepMaxOutputBytes is deliberately far above the executor's 4 MiB
// default because for semgrep, unlike every other tool routed through the
// chokepoint, STDOUT IS THE RESULT: it is the JSON document this adapter
// parses. A cut stream is not a shortened log, it is an unparseable
// document. 64 MiB covers a --config=auto run over a large monorepo and is
// still bounded, where the previous cmd.Output() buffered without limit.
//
// A var rather than a const so the truncation path can be exercised in a
// test without generating 64 MiB of output.
var semgrepMaxOutputBytes = 64 << 20

// Adapter runs semgrep as a subprocess.
//
// Exec is the injection seam. A struct field (rather than a functional
// option or a locally-declared interface) is the right shape here because
// Adapter is already a constructed struct held in a staticcheck.Registry,
// and a field leaves every existing New() call site — internal/scanner/all
// and the adapter's own tests — compiling unchanged. Nil means "run the
// tool, record nothing", which is what a standalone or test caller with no
// event stream needs.
type Adapter struct {
	Exec executor.Executor
}

func New() *Adapter { return &Adapter{} }

// NewWithExecutor returns an Adapter that routes its subprocess through
// exec, so the call leaves a tool_call_started / tool_call_completed pair
// in the run's event stream.
func NewWithExecutor(exec executor.Executor) *Adapter { return &Adapter{Exec: exec} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	args := []string{"--json", "--no-git-ignore"}

	configPath := "auto"
	if v, ok := req.ExtraArgs["config"]; ok && v != "" {
		configPath = v
	}
	args = append(args, "--config="+configPath)

	for _, f := range req.TargetFiles {
		args = append(args, "--include="+f)
	}

	args = append(args, req.RepoRoot)

	res := executor.OrLocal(a.Exec).Run(ctx, executor.Request{
		Name:    "semgrep",
		Command: "semgrep",
		Args:    args,
		Profile: executor.Profile{
			// --config=auto resolves rules from the semgrep registry, so
			// this call reaches the network by design. Write stays none:
			// semgrep reports on stdout and touches nothing.
			Network:        executor.NetworkAllow,
			Write:          executor.WriteNone,
			Timeout:        semgrepTimeout,
			MaxOutputBytes: semgrepMaxOutputBytes,
			// Parity: the previous exec.CommandContext left cmd.Env nil,
			// so the child inherited everything. See InheritedEnvNames.
			EnvAllowlist: executor.InheritedEnvNames(),
		},
	})

	// Error/ExitCode split, preserved verbatim from the os/exec version:
	// a NON-ZERO EXIT IS A NORMAL SEMGREP OUTCOME (it exits non-zero when
	// it found something), so only a true execution failure — res.Error,
	// i.e. timeout or binary-not-found — is fatal here. Everything else
	// falls through to the parser exactly as before, including the
	// substitution of stderr for an empty stdout.
	if res.Error != "" {
		return nil, fmt.Errorf("semgrep exec: %s", res.Error)
	}
	out := res.Stdout
	if !res.OK && len(out) == 0 {
		out = res.Stderr
	}
	if res.Truncated {
		// Refuse rather than hand the parser a document that is missing
		// its tail: parseSemgrepJSON would report a syntax error that
		// says nothing about the real cause. The event carries
		// truncated=true for the same call.
		return nil, fmt.Errorf("semgrep output exceeded the %d-byte cap and was truncated; "+
			"refusing to parse a partial JSON document", semgrepMaxOutputBytes)
	}

	return parseSemgrepJSON(out)
}

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
}

func parseSemgrepJSON(data []byte) ([]staticcheck.CheckFinding, error) {
	var output semgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}

	findings := make([]staticcheck.CheckFinding, 0, len(output.Results))
	for _, r := range output.Results {
		findings = append(findings, staticcheck.CheckFinding{
			ToolName:  "semgrep",
			RuleID:    r.CheckID,
			Path:      r.Path,
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
			Message:   r.Extra.Message,
			Severity:  normalizeSeverity(r.Extra.Severity),
			Snippet:   r.Extra.Lines,
		})
	}
	return findings, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	default:
		return "info"
	}
}
