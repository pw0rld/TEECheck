package repomix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// repomixTimeout bounds a call that previously had no bound of its own
// beyond the caller's context, which at both call sites is
// context.Background(). 20 minutes is generous on purpose: the first `npx
// repomix` in a fresh environment downloads the package from the npm
// registry before it does any work, and a monorepo pack is minutes on top
// of that.
const repomixTimeout = 20 * time.Minute

type PackRequest struct {
	RepoRoot    string
	TargetFiles []string
	Compress    bool

	// Exec is the injection seam. Pack is a package-level function with a
	// single parameter object and no receiver to hang state on, so the
	// request struct is the only injection point this API has; introducing
	// a Packer type would rewrite every call site to buy nothing. The
	// field is wiring, not a query parameter — it is not part of what gets
	// packed and PackRequest is never serialized.
	//
	// Nil means "run repomix, record nothing", which is what the planner
	// action gets when a test constructs an ActionRequest without an
	// executor.
	Exec executor.Executor
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

	res := executor.OrLocal(req.Exec).Run(ctx, executor.Request{
		Name:    "repomix",
		Command: "npx",
		Args:    args,
		Profile: executor.Profile{
			// npx fetches the repomix package from the npm registry, and
			// repomix writes the --style json report to the -o temp file.
			Network:        executor.NetworkAllow,
			Write:          executor.WriteWorkspace,
			Timeout:        repomixTimeout,
			MaxOutputBytes: 0, // executor default: the report is the -o file, not stdout
			// Parity: the previous exec.CommandContext left cmd.Env nil,
			// so the child inherited everything — including the npm
			// config npx itself reads.
			EnvAllowlist: executor.InheritedEnvNames(),
		},
	})
	// The previous implementation set cmd.Stderr = os.Stderr, so npx's
	// progress and errors appeared on the operator's terminal. Routing
	// through the executor captures stderr into the record instead, so
	// replay it here to keep that output visible. Buffered rather than
	// streamed is the only observable difference.
	if len(res.Stderr) > 0 {
		_, _ = os.Stderr.Write(res.Stderr)
	}
	if err := res.Err(); err != nil {
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
