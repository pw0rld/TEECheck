// Package codeql wraps the CodeQL CLI: building databases, running TWE query
// modules, and parsing the resulting SARIF into structured results the Solver
// consumes. It is the M2 fact engine — the deterministic source of evidence
// for TWE verdicts. Verified viable by the M2 spike (see
// docs/design/M2-codeql-spike.md).
package codeql

import (
	"encoding/json"
	"fmt"
)

// Result is one SARIF finding, flattened to the fields the pipeline needs: a
// rule id, a human message, a severity level, and a precise source location.
type Result struct {
	RuleID      string `json:"rule_id"`
	Message     string `json:"message"`
	Level       string `json:"level,omitempty"`
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

// sarifLog is the subset of the SARIF 2.1.0 schema we read. Everything else is
// ignored so a newer CodeQL emitting extra fields does not break parsing.
type sarifLog struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
						EndLine     int `json:"endLine"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// ParseSARIF flattens a SARIF 2.1.0 log into Results. A result with no
// location still yields a Result (with an empty Path) so nothing is silently
// dropped; callers decide how to treat locationless findings.
func ParseSARIF(data []byte) ([]Result, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	var out []Result
	for _, run := range log.Runs {
		for _, r := range run.Results {
			res := Result{
				RuleID:  r.RuleID,
				Message: r.Message.Text,
				Level:   r.Level,
			}
			if len(r.Locations) > 0 {
				phys := r.Locations[0].PhysicalLocation
				res.Path = phys.ArtifactLocation.URI
				res.StartLine = phys.Region.StartLine
				res.StartColumn = phys.Region.StartColumn
				res.EndLine = phys.Region.EndLine
				res.EndColumn = phys.Region.EndColumn
			}
			out = append(out, res)
		}
	}
	return out, nil
}
