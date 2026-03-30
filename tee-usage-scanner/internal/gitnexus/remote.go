package gitnexus

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const remoteExportTimeout = 10 * time.Minute

type RemoteExporter struct {
	SSHTarget    string
	ScriptPath   string
	GitNexusRoot string
}

func (r RemoteExporter) ExportGraph(sourcePath, outPath string) (string, error) {
	if strings.TrimSpace(r.SSHTarget) == "" {
		return "", fmt.Errorf("remote export requires an SSH target")
	}
	if strings.TrimSpace(sourcePath) == "" {
		return "", fmt.Errorf("remote export requires a source path")
	}
	if strings.TrimSpace(outPath) == "" {
		return "", fmt.Errorf("remote export requires an output path")
	}

	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return "", fmt.Errorf("resolve source path: %w", err)
	}
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return "", fmt.Errorf("resolve graph output path: %w", err)
	}

	scriptPath := strings.TrimSpace(r.ScriptPath)
	if scriptPath == "" {
		scriptPath = filepath.Clean("scripts/gitnexus/export_graph.mjs")
	}
	absScript, err := filepath.Abs(scriptPath)
	if err != nil {
		return "", fmt.Errorf("resolve export script path: %w", err)
	}

	remoteCommand := fmt.Sprintf(
		"node %s --repo %s --out %s%s",
		shellQuote(absScript),
		shellQuote(absSource),
		shellQuote(absOut),
		optionalGitNexusRootArg(strings.TrimSpace(r.GitNexusRoot)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), remoteExportTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", "-T", r.SSHTarget, remoteCommand)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("execute remote GitNexus export via ssh %q: %w\n%s", r.SSHTarget, err, strings.TrimSpace(string(output)))
	}

	return absOut, nil
}

func optionalGitNexusRootArg(root string) string {
	if root == "" {
		return ""
	}
	return " --gitnexus-root " + shellQuote(root)
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
