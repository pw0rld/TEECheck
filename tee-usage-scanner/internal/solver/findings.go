package solver

import (
	"fmt"
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// BuildFindings converts solver verdicts into the shared findings artifact
// (the same schema the arbiter writes and the benchmark scorer reads). Every
// verdict is recorded — including cleared and non-applicable ones — so the run
// is a complete audit trail; consumers filter by Status.
func BuildFindings(runID string, results []Result) artifacts.Findings {
	doc := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         runID,
		Findings:      make([]artifacts.FindingItem, 0, len(results)),
	}
	for _, r := range results {
		doc.Findings = append(doc.Findings, artifacts.FindingItem{
			FindingID:  r.TWEID + ":" + r.SiteID,
			SliceID:    r.SiteID,
			Status:     string(r.Status),
			Severity:   severityFor(r),
			Confidence: confidenceFor(r.Status),
			Files:      evidenceFiles(r.Evidence),
			Summary:    fmt.Sprintf("%s (%s): %s", r.TWEID, r.Status, r.Reason),
			Evidence:   evidenceLines(r.Evidence),
		})
	}
	return doc
}

func severityFor(r Result) string {
	// Prefer the SARIF level when present; otherwise derive from the verdict.
	for _, e := range r.Evidence {
		if e.Level != "" {
			return e.Level
		}
	}
	switch r.Status {
	case Confirmed:
		return "error"
	case ViolatedCandidate, ConfigurationDependent:
		return "warning"
	default:
		return "info"
	}
}

func confidenceFor(s Status) string {
	switch s {
	case Confirmed:
		return "high"
	case ViolatedCandidate, ConfigurationDependent:
		return "medium"
	case Unresolved:
		return "low"
	default:
		return "low"
	}
}

func evidenceFiles(evidence []codeql.Result) []string {
	seen := map[string]bool{}
	var files []string
	for _, e := range evidence {
		if e.Path != "" && !seen[e.Path] {
			seen[e.Path] = true
			files = append(files, e.Path)
		}
	}
	sort.Strings(files)
	return files
}

func evidenceLines(evidence []codeql.Result) []string {
	var lines []string
	for _, e := range evidence {
		line := fmt.Sprintf("%s @ %s:%d", e.RuleID, e.Path, e.StartLine)
		if e.Message != "" {
			line += ": " + e.Message
		}
		lines = append(lines, line)
	}
	return lines
}
