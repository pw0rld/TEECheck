package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

const ripgrepMaxMatchLines = 200

// RipgrepNoMatchOutput is what a successful search with zero matches
// reports. An empty Output is dropped from the round observation by
// omitempty, leaving the model an ok=true with no output field — which reads
// the same as a tool that ran and produced nothing for an unrelated reason.
// "I searched and found nothing" is a real answer and has to be stated.
const RipgrepNoMatchOutput = "(no matches)"

// ripgrepLegalArgs is quoted back when an unknown argument arrives, so the
// model can correct itself on the next round the same way an unknown
// fact_layer_query operation is handled.
const ripgrepLegalArgs = `"pattern" (required), "globs"`

type ripgrepArgs struct {
	Pattern string   `json:"pattern"`
	Globs   []string `json:"globs"`
}

// RipgrepHandler implements the ripgrep action. It routes through
// internal/executor — the chokepoint for subprocess tools — so
// timeout, output capping, and tool_call_* event emission are
// handled centrally and uniformly with future semgrep / codeql /
// go test integrations.
//
// Pattern is passed to rg as a separate argv element, never
// concatenated into a shell command, so pattern injection is not
// possible.
type RipgrepHandler struct{}

func (RipgrepHandler) Name() string { return "ripgrep" }

// IsExecutorBacked tells the planner registry that this handler
// emits its own tool_call_* events via the executor, so the
// planner should skip its manual emission path for ripgrep calls.
func (RipgrepHandler) IsExecutorBacked() bool { return true }

func (RipgrepHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args ripgrepArgs
	dec := json.NewDecoder(bytes.NewReader(req.Args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&args); err != nil {
		return fail("ripgrep", fmt.Sprintf("invalid args: %v; legal args are %s", err, ripgrepLegalArgs))
	}
	if strings.TrimSpace(args.Pattern) == "" {
		return fail("ripgrep", "pattern is required")
	}
	if req.Executor == nil {
		return fail("ripgrep", "executor not provided in ActionRequest "+
			"(executor-backed handlers require explicit wiring)")
	}

	cmdArgs := []string{"--line-number", "--no-heading", "--color=never"}
	for _, g := range args.Globs {
		if strings.TrimSpace(g) == "" {
			continue
		}
		cmdArgs = append(cmdArgs, "--glob", g)
	}
	cmdArgs = append(cmdArgs, "--", args.Pattern, req.RepoRoot)

	res := req.Executor.Run(ctx, executor.Request{
		Name:    "ripgrep",
		Command: "rg",
		Args:    cmdArgs,
		// ripgrep matches --glob patterns against paths relative to the
		// working directory. RepoRoot is passed as an absolute search path,
		// so without this every glob containing a separator was matched
		// against an absolute candidate path and could never hold —
		// "core/crypto/*.c" silently selected nothing while a bare "*.c"
		// kept working (those match the basename). Anchoring the working
		// directory at the repo root makes path-qualified globs mean what
		// they say; the search path stays absolute so match lines remain
		// absolute for planner.trackObservedPaths.
		WorkDir: req.RepoRoot,
		Profile: executor.Profile{
			Network:        executor.NetworkNone,
			Write:          executor.WriteNone,
			Timeout:        30 * time.Second,
			MaxOutputBytes: 4 * 1024 * 1024,
		},
		RunID: req.RunID,
		Agent: req.Agent,
		Round: req.Round,
	})

	// Error/ExitCode contract per docs/EVENT_SCHEMA.md:
	//   - res.Error != ""    : true execution failure (timeout, rg
	//                          missing, ctx cancelled, ...)
	//   - res.ExitCode == 0  : matches found
	//   - res.ExitCode == 1  : no matches — normal, OK=true with
	//                          RipgrepNoMatchOutput as the Output
	//   - res.ExitCode other : abnormal rg failure (syntax error in
	//                          pattern, glob parse, etc.) — surface
	//                          as action failure with stderr context
	if res.Error != "" {
		// "binary not found: rg" is one of the common shapes; keep
		// the upstream error string verbatim so the planner LLM can
		// react ("rg not installed" → switch to a different action).
		if strings.Contains(res.Error, "binary not found") {
			return fail("ripgrep", "ripgrep (rg) not installed")
		}
		return fail("ripgrep", res.Error)
	}
	switch res.ExitCode {
	case 0:
		// matches; fall through
	case 1:
		return ActionResult{Name: "ripgrep", OK: true, Output: RipgrepNoMatchOutput, DurationMs: res.DurationMs}
	default:
		stderr := strings.TrimSpace(string(res.Stderr))
		msg := fmt.Sprintf("ripgrep exit %d", res.ExitCode)
		if stderr != "" {
			msg += ": " + truncateOneLine(stderr, 240)
		}
		return ActionResult{
			Name:       "ripgrep",
			OK:         false,
			Error:      msg,
			DurationMs: res.DurationMs,
		}
	}

	text := strings.TrimRight(string(res.Stdout), "\n")
	if text == "" {
		return ActionResult{Name: "ripgrep", OK: true, Output: RipgrepNoMatchOutput, DurationMs: res.DurationMs}
	}
	lines := strings.Split(text, "\n")
	truncated := res.Truncated
	if len(lines) > ripgrepMaxMatchLines {
		lines = lines[:ripgrepMaxMatchLines]
		truncated = true
	}
	return ActionResult{
		Name:       "ripgrep",
		OK:         true,
		Output:     strings.Join(lines, "\n"),
		Truncated:  truncated,
		DurationMs: res.DurationMs,
	}
}

// truncateOneLine flattens stderr to a single line and caps it. Used
// only to embed a short context hint in the action's Error string.
func truncateOneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
