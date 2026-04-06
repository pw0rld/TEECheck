package grep

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "grep" }
func (a *Adapter) Available() bool { return true }

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	keywords := lowerAll(req.Keywords)
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
			dirFindings, err := walkDir(ctx, full, req.RepoRoot, keywords)
			if err != nil {
				return findings, err
			}
			findings = append(findings, dirFindings...)
		} else {
			fileFindings := searchFile(full, req.RepoRoot, keywords)
			findings = append(findings, fileFindings...)
		}
	}
	return findings, nil
}

func walkDir(ctx context.Context, dir, repoRoot string, keywords []string) ([]staticcheck.CheckFinding, error) {
	var findings []staticcheck.CheckFinding
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		findings = append(findings, searchFile(path, repoRoot, keywords)...)
		return nil
	})
	return findings, err
}

func searchFile(fullPath, repoRoot string, keywords []string) []staticcheck.CheckFinding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	rel, err := filepath.Rel(repoRoot, fullPath)
	if err != nil {
		rel = fullPath
	}

	var findings []staticcheck.CheckFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, staticcheck.CheckFinding{
					ToolName:  "grep",
					Path:      filepath.ToSlash(rel),
					StartLine: lineNum,
					Message:   strings.TrimSpace(line),
					Severity:  "info",
					Snippet:   strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return findings
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
