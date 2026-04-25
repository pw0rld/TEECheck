package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

const ripgrepMaxMatchLines = 200

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
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("ripgrep", fmt.Sprintf("invalid args: %v", err))
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
	//                          empty Output
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
		return ActionResult{Name: "ripgrep", OK: true, Output: "", DurationMs: res.DurationMs}
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
		return ActionResult{Name: "ripgrep", OK: true, Output: "", DurationMs: res.DurationMs}
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
