package staticcheck

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("adapter not implemented")

type CheckRequest struct {
	RepoRoot    string
	TargetFiles []string
	Keywords    []string
	RuleIDs     []string
	Category    string
	ExtraArgs   map[string]string
}

type CheckFinding struct {
	ToolName  string `json:"tool_name"`
	RuleID    string `json:"rule_id,omitempty"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line,omitempty"`
	Message   string `json:"message"`
	Severity  string `json:"severity,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

type Adapter interface {
	Name() string
	Available() bool
	Run(ctx context.Context, req CheckRequest) ([]CheckFinding, error)
}
