package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// LocalExecutor runs commands in the current process via os/exec.
// It enforces timeout and output-byte caps, records Profile metadata
// on emitted events, and otherwise stays out of the way.
//
// Network and write policy are NOT enforced today. The fields are
// honored as event metadata so consumers can already see what each
// call site claimed; a future SandboxExecutor will pick those up
// and turn them into kernel-level constraints.
type LocalExecutor struct {
	// Recorder, when non-nil, receives tool_call_started before the
	// process is launched and tool_call_completed after it exits.
	// When nil, the executor stays silent — useful for tests and for
	// call sites that emit their own events.
	Recorder events.Recorder
	// Blobs, when non-nil, is used to store the args list as a blob
	// so the started event can reference them by sha256 ref instead
	// of inlining a possibly-large argv. When nil, args are not
	// blobbed; the tool_args_blob field stays empty.
	Blobs *events.BlobStore
}

// Run executes req under the given context. The returned Result is
// always non-zero — even policy denials and binary-not-found produce
// a populated Result with Error set.
func (e *LocalExecutor) Run(ctx context.Context, req Request) Result {
	timeout := req.Profile.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxOut := req.Profile.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = DefaultMaxOutputBytes
	}

	e.emitStarted(req)

	if req.Command == "" {
		res := Result{Error: "executor: empty command"}
		e.emitCompleted(req, res)
		return res
	}

	// We always wrap with a timeout context, even if the caller
	// already set a deadline — the inner cancel is harmless and
	// guarantees we honor Profile.Timeout.
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, req.Command, req.Args...)
	if req.WorkDir != "" {
		// A relative working directory is resolved twice: once here, and
		// again by any tool that was handed the same path as an argument.
		// ripgrep is given its search root both ways, so a relative root
		// made it cd into the tree and then look for the tree inside
		// itself — 17 consecutive calls across three runs returned "No
		// such file or directory" while read_file in the same round
		// succeeded, and nothing surfaced it. This is the one place every
		// subprocess in the system passes through, so the rule belongs
		// here rather than in each tool's comments.
		if !filepath.IsAbs(req.WorkDir) {
			res := Result{Error: fmt.Sprintf("executor: work dir must be absolute, got %q — "+
				"a relative path is resolved against the subprocess's own directory "+
				"and silently finds nothing", req.WorkDir)}
			e.emitCompleted(req, res)
			return res
		}
		cmd.Dir = req.WorkDir
	}

	// Env handling: build an explicit env from the allowlist + any
	// caller-provided overrides. Empty allowlist means "inherit a
	// safe minimum" — we always pass PATH so the binary is
	// resolvable, and HOME so tools that read user config don't
	// silently misbehave.
	cmd.Env = buildEnv(req.Profile.EnvAllowlist, req.Env)

	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}

	stdoutBuf := newCapBuffer(maxOut)
	stderrBuf := newCapBuffer(maxOut)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start).Milliseconds()

	res := Result{
		Stdout:     stdoutBuf.Bytes(),
		Stderr:     stderrBuf.Bytes(),
		DurationMs: dur,
		Truncated:  stdoutBuf.truncated || stderrBuf.truncated,
	}

	// Error/ExitCode contract:
	//   - Process started and exited (0 or non-zero) → ExitCode is
	//     authoritative; Error stays empty. This lets callers like
	//     ripgrep (exit 1 = no matches) and semgrep (non-zero with
	//     valid JSON output) distinguish "tool said no" from a real
	//     execution failure by checking Error instead of OK.
	//   - True execution failures (timeout, binary not found, exec
	//     errors that prevent obtaining an exit code) populate Error
	//     and leave ExitCode at zero.
	//   - OK is true iff the process exited 0 AND no error fired.
	switch {
	case runErr == nil:
		res.OK = true
		res.ExitCode = 0
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		res.Error = "executor: timeout after " + timeout.String()
	case errors.Is(runErr, exec.ErrNotFound) || isExecNotFound(runErr):
		res.Error = "executor: binary not found: " + req.Command
	default:
		// If the process actually started and exited non-zero,
		// ExitError carries the code — that is a normal tool
		// outcome, not an execution failure, so Error stays empty.
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.Error = "executor: " + runErr.Error()
		}
	}

	e.emitCompleted(req, res)
	return res
}

func (e *LocalExecutor) emitStarted(req Request) {
	if e.Recorder == nil {
		return
	}
	// Args list is plain text — render as one-per-line so blob
	// content is grep-friendly when inspected manually.
	argsBlob := events.BestEffortRef(e.Blobs, []byte(strings.Join(req.Args, "\n")))
	timeout := req.Profile.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxOut := req.Profile.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = DefaultMaxOutputBytes
	}
	_ = e.Recorder.Emit(events.ToolCallExecutorStarted(
		req.RunID, req.Agent, toolNameOrCommand(req), req.Round,
		argsBlob,
		string(req.Profile.Network),
		string(req.Profile.Write),
		timeout.Milliseconds(),
		maxOut,
	))
}

func (e *LocalExecutor) emitCompleted(req Request, res Result) {
	if e.Recorder == nil {
		return
	}
	// Both streams are blobbed unconditionally, failures included. No
	// extra cap is applied here: Stdout/Stderr already arrive bounded
	// by Profile.MaxOutputBytes (capBuffer), and when that bound bit,
	// res.Truncated is true and travels on this very event — so a
	// shortened blob is never silent. A second cap at this layer would
	// add a truncation point that says nothing, which is the exact
	// defect this instrumentation exists to close.
	_ = e.Recorder.Emit(events.ToolCallExecutorCompleted(
		req.RunID, req.Agent, toolNameOrCommand(req), req.Round,
		res.OK, res.ExitCode, res.DurationMs, res.Truncated,
		events.BestEffortRef(e.Blobs, res.Stdout),
		events.BestEffortRef(e.Blobs, res.Stderr),
		res.Error,
	))
}

func toolNameOrCommand(req Request) string {
	if req.Name != "" {
		return req.Name
	}
	return req.Command
}

// buildEnv constructs the env passed to the child process. The
// allowlist names variables to inherit from os.Environ(); overrides
// then layer on top. PATH and HOME are always inherited so binaries
// resolve and tools find their config.
func buildEnv(allowlist []string, overrides map[string]string) []string {
	want := map[string]bool{"PATH": true, "HOME": true}
	for _, name := range allowlist {
		want[name] = true
	}
	out := make([]string, 0, len(want)+len(overrides))
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if want[kv[:i]] {
			out = append(out, kv)
		}
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

// capBuffer is an io.Writer that retains at most cap bytes and sets
// truncated=true if more were attempted. Subsequent writes past the
// cap are discarded silently — the goal is bounding memory, not
// producing a faithful copy.
type capBuffer struct {
	buf       *bytes.Buffer
	cap       int
	truncated bool
}

func newCapBuffer(cap int) *capBuffer {
	return &capBuffer{buf: &bytes.Buffer{}, cap: cap}
}

func (b *capBuffer) Write(p []byte) (int, error) {
	remaining := b.cap - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) <= remaining {
		return b.buf.Write(p)
	}
	b.buf.Write(p[:remaining])
	b.truncated = true
	return len(p), nil
}

func (b *capBuffer) Bytes() []byte { return b.buf.Bytes() }

// guard against unused import on platforms where ErrNotFound is not
// the only "binary missing" indication
var _ = io.EOF

func isExecNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "executable file not found")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
