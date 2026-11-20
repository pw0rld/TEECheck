package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type sourceHunk struct {
	path   string
	before []string
	after  []string
}

// fixturePatchHunks ignores mail footers and preserves exact source whitespace.
func fixturePatchHunks(patch string) []sourceHunk {
	var result []sourceHunk
	var h sourceHunk
	path := ""
	active := false
	flush := func() {
		if active {
			result = append(result, h)
		}
		active = false
	}
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case line == "-- ":
			flush()
		case strings.HasPrefix(line, "diff --git "):
			flush()
			path = ""
		case strings.HasPrefix(line, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
		case strings.HasPrefix(line, "@@ "):
			flush()
			h = sourceHunk{path: path}
			active = true
		case active && strings.HasPrefix(line, " "):
			h.before = append(h.before, line[1:])
			h.after = append(h.after, line[1:])
		case active && strings.HasPrefix(line, "-"):
			h.before = append(h.before, line[1:])
		case active && strings.HasPrefix(line, "+"):
			h.after = append(h.after, line[1:])
		}
	}
	flush()
	return result
}

func sourceContainsHunk(source string, lines []string) bool {
	return len(lines) > 0 && strings.Contains("\n"+strings.TrimSuffix(source, "\n")+"\n", "\n"+strings.Join(lines, "\n")+"\n")
}

// validateFixturePatch checks only files included in the fixture subset. It
// catches reversed or unrelated source pairs even when their hashes agree
// with the oracle: hashes establish identity, not vulnerability direction.
func validateFixturePatch(dir string, oracle oracleSpec) error {
	patch, err := os.ReadFile(filepath.Join(dir, "patches", "fix.patch"))
	if err != nil {
		return err
	}
	checked := 0
	for _, h := range fixturePatchHunks(string(patch)) {
		file := ""
		for _, f := range oracle.Files {
			if h.path == f.Path || strings.HasSuffix(h.path, "/"+f.Path) {
				file = f.Path
				break
			}
		}
		if file == "" {
			continue
		}
		before, err := os.ReadFile(filepath.Join(dir, "vulnerable", file))
		if err != nil {
			return err
		}
		after, err := os.ReadFile(filepath.Join(dir, "fixed", file))
		if err != nil {
			return err
		}
		checked++
		if !sourceContainsHunk(string(before), h.before) || !sourceContainsHunk(string(after), h.after) {
			return fmt.Errorf("fixture direction/content does not match fix.patch for %s hunk %d; mark requires_review until its source provenance is resolved", file, checked)
		}
	}
	if checked == 0 {
		return fmt.Errorf("no fix.patch hunks map to fixture files")
	}
	return nil
}
