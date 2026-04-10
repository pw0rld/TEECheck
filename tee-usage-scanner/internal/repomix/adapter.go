package repomix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type PackRequest struct {
	RepoRoot    string
	TargetFiles []string
	Compress    bool
}

type PackResult struct {
	FileSummary        any               `json:"fileSummary"`
	DirectoryStructure string            `json:"directoryStructure"`
	Files              map[string]string `json:"files"`
}

func Available() bool {
	_, err := exec.LookPath("npx")
	return err == nil
}

func Pack(ctx context.Context, req PackRequest) (PackResult, error) {
	args := []string{"repomix", req.RepoRoot, "--style", "json"}

	if req.Compress {
		args = append(args, "--compress")
	}

	for _, f := range req.TargetFiles {
		args = append(args, "--include", f)
	}

	tmpFile, err := os.CreateTemp("", "repomix-*.json")
	if err != nil {
		return PackResult{}, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args = append(args, "-o", tmpPath)

	cmd := exec.CommandContext(ctx, "npx", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return PackResult{}, fmt.Errorf("repomix: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return PackResult{}, fmt.Errorf("read repomix output: %w", err)
	}

	var result PackResult
	if err := json.Unmarshal(data, &result); err != nil {
		return PackResult{}, fmt.Errorf("parse repomix json: %w", err)
	}

	return result, nil
}

func FormatForPrompt(result PackResult, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 8000
	}
	var b strings.Builder
	for path, content := range result.Files {
		entry := fmt.Sprintf("=== %s ===\n%s\n\n", path, content)
		if b.Len()+len(entry) > maxLen {
			b.WriteString(fmt.Sprintf("... (%d more files truncated)\n", len(result.Files)-countFiles(b.String())))
			break
		}
		b.WriteString(entry)
	}
	return b.String()
}

func countFiles(s string) int {
	return strings.Count(s, "=== ")
}
