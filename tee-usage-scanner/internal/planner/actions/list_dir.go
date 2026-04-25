package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const listDirMaxDepth = 3

type listDirArgs struct {
	Path  string `json:"path"`
	Depth int    `json:"depth"`
}

// ListDirHandler implements the list_dir action — a recursive directory
// listing bounded by a depth cap of 3.
type ListDirHandler struct{}

func (ListDirHandler) Name() string { return "list_dir" }

func (ListDirHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args listDirArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("list_dir", fmt.Sprintf("invalid args: %v", err))
	}
	if args.Path == "" {
		args.Path = "."
	}
	if args.Depth < 0 {
		args.Depth = 0
	}
	if args.Depth > listDirMaxDepth {
		args.Depth = listDirMaxDepth
	}

	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("list_dir", err.Error())
	}

	info, err := os.Stat(full)
	if err != nil {
		return fail("list_dir", err.Error())
	}
	if !info.IsDir() {
		return fail("list_dir", fmt.Sprintf("%s is not a directory", args.Path))
	}

	var buf strings.Builder
	if err := walkDir(ctx, full, 0, args.Depth, &buf); err != nil {
		return fail("list_dir", err.Error())
	}
	return ActionResult{Name: "list_dir", OK: true, Output: buf.String()}
}

func walkDir(ctx context.Context, dir string, depth, maxDepth int, buf *strings.Builder) error {
	if depth > maxDepth {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	indent := strings.Repeat("  ", depth)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			fmt.Fprintf(buf, "%s%s/\n", indent, name)
			if depth < maxDepth {
				if err := walkDir(ctx, filepath.Join(dir, name), depth+1, maxDepth, buf); err != nil {
					return err
				}
			}
		} else {
			fmt.Fprintf(buf, "%s%s\n", indent, name)
		}
	}
	return nil
}
