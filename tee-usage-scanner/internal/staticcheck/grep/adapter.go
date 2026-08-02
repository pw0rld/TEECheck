package grep

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string    { return "grep" }
func (a *Adapter) Available() bool { return true }

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	keywords := expandKeywords(req)
	if len(keywords) == 0 {
		return nil, nil
	}
	targets := req.TargetFiles
	if len(targets) == 0 {
		targets = []string{"."}
	}

	var findings []staticcheck.CheckFinding
	for _, rel := range targets {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		full := filepath.Join(req.RepoRoot, rel)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.IsDir() {
			dirFindings, err := walkDir(ctx, full, req.RepoRoot, keywords, req.Category)
			if err != nil {
				return findings, err
			}
			findings = append(findings, dirFindings...)
		} else {
			fileFindings := searchFile(full, req.RepoRoot, keywords, req.Category)
			findings = append(findings, fileFindings...)
		}
	}
	return findings, nil
}

// expandKeywords turns the planner's natural-language obligations into a
// small, generic vocabulary. It deliberately contains no CVE, function, or
// patch identifiers; the grep adapter is only a candidate generator.
func expandKeywords(req staticcheck.CheckRequest) []string {
	keywords := lowerAll(req.Keywords)
	common := map[string][]string{
		"boundary":       {"untrusted", "input", "param", "bound", "bounds", "array", "validate", "cleanup"},
		"key_management": {"alloc", "free", "release", "key", "error", "null", "crypto"},
		"state":          {"panic", "crash", "context", "state", "restart", "alive"},
	}
	keywords = append(keywords, common[strings.ToLower(strings.TrimSpace(req.Category))]...)
	return uniqueKeywords(keywords)
}

func uniqueKeywords(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// skippedDirs are directories that hold no source to audit. Walking them is
// not merely wasteful: .git/index and the pack files embed source paths as
// plain strings inside binary records, so a keyword search matches them and
// returns raw bytes as evidence. On 2026-08-02, 96 such "findings" — NUL
// bytes and all — reached the verifier's and arbiter's prompts.
//
// This mattered only once the scanner was pointed at a real checkout. Before
// that its root was a benchmark fixture holding a single .c file, with no
// .git to walk, and the walk's complete lack of filtering was invisible.
var skippedDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true,
	"out": true, "build": true, "target": true,
}

func walkDir(ctx context.Context, dir, repoRoot string, keywords []string, category string) ([]staticcheck.CheckFinding, error) {
	var findings []staticcheck.CheckFinding
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skippedDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		findings = append(findings, searchFile(path, repoRoot, keywords, category)...)
		return nil
	})
	return findings, err
}

// binarySniffBytes is how much of a file is examined for NUL. git and
// ripgrep both decide the same way and at a similar depth; a text file with
// a NUL in its first 8 KiB is not a file this scanner can report lines from.
const binarySniffBytes = 8192

// looksBinary reports whether the opened file appears to be binary, by the
// same rule git and ripgrep use: a NUL byte near the start.
//
// A directory blocklist alone cannot be right — it is a list of the places
// binaries were last found, and the checkout also carries keys/, images and
// build artefacts. NUL detection needs no list and stays correct for files
// nobody thought of.
func looksBinary(f *os.File) (bool, error) {
	buf := make([]byte, binarySniffBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	if _, serr := f.Seek(0, io.SeekStart); serr != nil {
		return false, serr
	}
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}

func searchFile(fullPath, repoRoot string, keywords []string, category string) []staticcheck.CheckFinding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// A binary file has no lines to report. Its bytes would arrive
	// downstream as quoted "evidence" with a path and a line number on them,
	// indistinguishable in shape from a real citation.
	if binary, berr := looksBinary(f); berr != nil || binary {
		return nil
	}

	rel, err := filepath.Rel(repoRoot, fullPath)
	if err != nil {
		rel = fullPath
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if groups := semanticGroups(category); len(groups) > 0 {
		return searchSemanticWindows(lines, rel, groups)
	}
	return searchKeywordLines(lines, rel, keywords)
}

func searchKeywordLines(lines []string, rel string, keywords []string) []staticcheck.CheckFinding {
	var findings []staticcheck.CheckFinding
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, staticcheck.CheckFinding{
					ToolName: "grep", Path: filepath.ToSlash(rel), StartLine: i + 1,
					Message: strings.TrimSpace(line), Severity: "info", Snippet: strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return findings
}

type semanticGroup struct {
	Name  string
	Terms []string
}

func semanticGroups(category string) []semanticGroup {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "boundary":
		return []semanticGroup{
			{Name: "external_input", Terms: []string{"untrusted", "input", "param", "argument", "caller"}},
			{Name: "bounds_or_storage", Terms: []string{"bound", "bounds", "array", "buffer", "index", "length"}},
			{Name: "validation_or_cleanup", Terms: []string{"validate", "check", "verify", "cleanup", "release", "free"}},
		}
	case "key_management":
		return []semanticGroup{
			{Name: "resource_operation", Terms: []string{"alloc", "create", "free", "release"}},
			{Name: "key_or_crypto", Terms: []string{"key", "crypto", "rsa", "bignum", "secret"}},
			{Name: "failure_or_null", Terms: []string{"error", "fail", "null", "panic", "return"}},
		}
	case "state", "lifecycle":
		return []semanticGroup{
			{Name: "abnormal_termination", Terms: []string{"panic", "crash", "failed", "abort"}},
			{Name: "state_or_context", Terms: []string{"state", "context", "session", "instance"}},
			{Name: "restart_or_retention", Terms: []string{"restart", "recreate", "keep", "alive", "retain"}},
		}
	}
	return nil
}

func searchSemanticWindows(lines []string, rel string, groups []semanticGroup) []staticcheck.CheckFinding {
	const window = 6
	var findings []staticcheck.CheckFinding
	for start := 0; start < len(lines); start++ {
		end := start + window
		if end > len(lines) {
			end = len(lines)
		}
		matched := make([]string, 0, len(groups))
		for _, group := range groups {
			for _, line := range lines[start:end] {
				lower := strings.ToLower(line)
				if containsAny(lower, group.Terms) {
					matched = append(matched, group.Name)
					break
				}
			}
		}
		if len(matched) < 2 {
			continue
		}
		findings = append(findings, staticcheck.CheckFinding{
			ToolName: "grep", RuleID: "generic-" + strings.ToLower(strings.ReplaceAll(rel, "/", "-")),
			Path: filepath.ToSlash(rel), StartLine: start + 1, EndLine: end,
			Message:  fmt.Sprintf("generic security window: %s", strings.Join(uniqueKeywords(matched), ", ")),
			Severity: "info", Snippet: strings.Join(trimLines(lines[start:end]), "\n"),
		})
		start = end - 1
	}
	return findings
}

func containsAny(line string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(line, term) {
			return true
		}
	}
	return false
}

func trimLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = strings.TrimSpace(line)
	}
	return out
}

func lowerAll(values []string) []string {
	var out []string
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
