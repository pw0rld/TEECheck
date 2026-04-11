package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const readFileLineCap = 500

type readFileArgs struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// ReadFileHandler implements the read_file action.
//
// Start and End are 1-indexed, inclusive. If End is 0 or negative, the
// handler reads up to the cap (500) starting from Start. Output is
// prefixed with line numbers so the LLM can reference lines back.
type ReadFileHandler struct{}

func (ReadFileHandler) Name() string { return "read_file" }

func (ReadFileHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args readFileArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("read_file", fmt.Sprintf("invalid args: %v", err))
	}
	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("read_file", err.Error())
	}
	info, err := os.Stat(full)
	if err != nil {
		return fail("read_file", err.Error())
	}
	if info.IsDir() {
		return fail("read_file", fmt.Sprintf("%s is a directory", args.Path))
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return fail("read_file", err.Error())
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if args.Start <= 0 {
		args.Start = 1
	}
	if args.End <= 0 {
		args.End = args.Start + readFileLineCap - 1
	}
	if args.End-args.Start+1 > readFileLineCap {
		args.End = args.Start + readFileLineCap - 1
	}

	if args.Start > len(lines) {
		return fail("read_file", fmt.Sprintf("start line %d beyond file end (%d)", args.Start, len(lines)))
	}
	if args.End > len(lines) {
		args.End = len(lines)
	}

	var buf strings.Builder
	for i := args.Start - 1; i < args.End; i++ {
		fmt.Fprintf(&buf, "%d: %s\n", i+1, lines[i])
	}

	truncated := (args.End - args.Start + 1) < len(lines)
	return ActionResult{Name: "read_file", OK: true, Output: buf.String(), Truncated: truncated}
}
