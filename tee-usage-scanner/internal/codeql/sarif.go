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
// RelatedLocation is a secondary site the result's message refers to. A
// thin-shell query names its entities through $@ placeholders, so the
// producer, the field and the authority call each arrive here with the
// symbol name as the location's message — which is the only place the
// symbol appears at all.
type RelatedLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	Symbol    string `json:"symbol,omitempty"`
}

type Result struct {
	RuleID      string            `json:"rule_id"`
	Message     string            `json:"message"`
	Related     []RelatedLocation `json:"related,omitempty"`
	Level       string            `json:"level,omitempty"`
	Path        string            `json:"path"`
	StartLine   int               `json:"start_line"`
	StartColumn int               `json:"start_column,omitempty"`
	EndLine     int               `json:"end_line,omitempty"`
	EndColumn   int               `json:"end_column,omitempty"`
	Paths       [][]PathStep      `json:"paths,omitempty"`
}

// PathStep is one node in a SARIF thread flow. Missing source coordinates
// remain explicit; relatedLocations are never substituted for a path.
type PathStep struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	Function    string `json:"function,omitempty"`
	Expression  string `json:"expression,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
	Index              *int   `json:"index"`
	ParentIndex        *int   `json:"parentIndex"`
}

type sarifLocation struct {
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI   string `json:"uri"`
			Index *int   `json:"index"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
			EndLine     int `json:"endLine"`
			EndColumn   int `json:"endColumn"`
			Snippet     struct {
				Text string `json:"text"`
			} `json:"snippet"`
		} `json:"region"`
		ContextRegion struct {
			Snippet struct {
				Text string `json:"text"`
			} `json:"snippet"`
		} `json:"contextRegion"`
	} `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifThreadFlowLocation struct {
	Location *sarifLocation `json:"location"`
	Index    *int           `json:"index"`
}

// sarifLog is the subset of the SARIF 2.1.0 schema we read. Everything else is
// ignored so a newer CodeQL emitting extra fields does not break parsing.
type sarifLog struct {
	Runs []struct {
		Artifacts []struct {
			Location struct {
				URI string `json:"uri"`
			} `json:"location"`
		} `json:"artifacts"`
		LogicalLocations    []sarifLogicalLocation    `json:"logicalLocations"`
		ThreadFlowLocations []sarifThreadFlowLocation `json:"threadFlowLocations"`
		Results             []struct {
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
			RelatedLocations []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"relatedLocations"`
			CodeFlows []struct {
				ThreadFlows []struct {
					Locations []sarifThreadFlowLocation `json:"locations"`
				} `json:"threadFlows"`
			} `json:"codeFlows"`
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
			for _, rl := range r.RelatedLocations {
				res.Related = append(res.Related, RelatedLocation{
					Path:      rl.PhysicalLocation.ArtifactLocation.URI,
					StartLine: rl.PhysicalLocation.Region.StartLine,
					Symbol:    rl.Message.Text,
				})
			}
			for _, flow := range r.CodeFlows {
				for _, thread := range flow.ThreadFlows {
					var path []PathStep
					for _, step := range thread.Locations {
						location := step.Location
						if location == nil && step.Index != nil && *step.Index >= 0 && *step.Index < len(run.ThreadFlowLocations) {
							location = run.ThreadFlowLocations[*step.Index].Location
						}
						if location == nil {
							// Keep the missing node, so a malformed path does not
							// become a shorter and apparently complete witness.
							path = append(path, PathStep{})
							continue
						}
						physical := location.PhysicalLocation
						uri := physical.ArtifactLocation.URI
						if uri == "" && physical.ArtifactLocation.Index != nil {
							i := *physical.ArtifactLocation.Index
							if i >= 0 && i < len(run.Artifacts) {
								uri = run.Artifacts[i].Location.URI
							}
						}
						expression := location.Message.Text
						if expression == "" {
							expression = physical.Region.Snippet.Text
						}
						if expression == "" {
							expression = physical.ContextRegion.Snippet.Text
						}
						path = append(path, PathStep{
							Path: uri, StartLine: physical.Region.StartLine, StartColumn: physical.Region.StartColumn,
							EndLine: physical.Region.EndLine, EndColumn: physical.Region.EndColumn,
							Function: sarifFunction(location.LogicalLocations, run.LogicalLocations), Expression: expression,
						})
					}
					res.Paths = append(res.Paths, path)
				}
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func sarifFunction(locations, table []sarifLogicalLocation) string {
	for _, original := range locations {
		logical := original
		seen := map[int]bool{}
		for {
			if logical.Index != nil && *logical.Index >= 0 && *logical.Index < len(table) && !seen[*logical.Index] {
				seen[*logical.Index] = true
				logical = table[*logical.Index]
			}
			if logical.Kind == "function" || logical.Kind == "member" || logical.Kind == "method" {
				if logical.FullyQualifiedName != "" {
					return logical.FullyQualifiedName
				}
				if logical.Name != "" {
					return logical.Name
				}
			}
			if logical.ParentIndex == nil || *logical.ParentIndex < 0 || *logical.ParentIndex >= len(table) || seen[*logical.ParentIndex] {
				break
			}
			seen[*logical.ParentIndex] = true
			logical = table[*logical.ParentIndex]
		}
	}
	return ""
}
