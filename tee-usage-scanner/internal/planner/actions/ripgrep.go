package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const ripgrepMaxMatchLines = 200

type ripgrepArgs struct {
	Pattern string   `json:"pattern"`
	Globs   []string `json:"globs"`
}

// RipgrepHandler implements the ripgrep action. It shells out to `rg`
// with --line-number --no-heading --color=never, passes the repo root
// as the search target, and caps output at ripgrepMaxMatchLines.
//
// Pattern is passed to rg as a separate argv element, never concatenated
// into a shell command, so pattern injection is not possible.
type RipgrepHandler struct{}

func (RipgrepHandler) Name() string { return "ripgrep" }

func (RipgrepHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args ripgrepArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("ripgrep", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Pattern) == "" {
		return fail("ripgrep", "pattern is required")
	}
	if _, err := exec.LookPath("rg"); err != nil {
		return fail("ripgrep", "ripgrep (rg) not installed")
	}

	cmdArgs := []string{"--line-number", "--no-heading", "--color=never"}
	for _, g := range args.Globs {
		if strings.TrimSpace(g) == "" {
			continue
		}
		cmdArgs = append(cmdArgs, "--glob", g)
	}
	cmdArgs = append(cmdArgs, "--", args.Pattern, req.RepoRoot)

	cmd := exec.CommandContext(ctx, "rg", cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return ActionResult{Name: "ripgrep", OK: true, Output: ""}
		}
		return fail("ripgrep", fmt.Sprintf("ripgrep exec: %v", err))
	}

	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return ActionResult{Name: "ripgrep", OK: true, Output: ""}
	}
	lines := strings.Split(text, "\n")
	truncated := false
	if len(lines) > ripgrepMaxMatchLines {
		lines = lines[:ripgrepMaxMatchLines]
		truncated = true
	}
	return ActionResult{
		Name:      "ripgrep",
		OK:        true,
		Output:    strings.Join(lines, "\n"),
		Truncated: truncated,
	}
}
