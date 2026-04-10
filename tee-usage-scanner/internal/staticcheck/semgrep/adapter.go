package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (a *Adapter) Run(ctx context.Context, req staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	args := []string{"--json", "--no-git-ignore"}

	configPath := "auto"
	if v, ok := req.ExtraArgs["config"]; ok && v != "" {
		configPath = v
	}
	args = append(args, "--config="+configPath)

	for _, f := range req.TargetFiles {
		args = append(args, "--include="+f)
	}

	args = append(args, req.RepoRoot)

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(out) == 0 {
				out = exitErr.Stderr
			}
		} else {
			return nil, fmt.Errorf("semgrep exec: %w", err)
		}
	}

	return parseSemgrepJSON(out)
}

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Lines    string `json:"lines"`
}

func parseSemgrepJSON(data []byte) ([]staticcheck.CheckFinding, error) {
	var output semgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}

	findings := make([]staticcheck.CheckFinding, 0, len(output.Results))
	for _, r := range output.Results {
		findings = append(findings, staticcheck.CheckFinding{
			ToolName:  "semgrep",
			RuleID:    r.CheckID,
			Path:      r.Path,
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
			Message:   r.Extra.Message,
			Severity:  normalizeSeverity(r.Extra.Severity),
			Snippet:   r.Extra.Lines,
		})
	}
	return findings, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	default:
		return "info"
	}
}
