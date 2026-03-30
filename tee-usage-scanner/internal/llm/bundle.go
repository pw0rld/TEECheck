package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/evidence"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/report"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/rules"
)

func WriteReviewBundle(dir string, rule rules.Rule, ev evidence.Package, finding report.Finding) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# TEE Usage Review Bundle\n\n")
	b.WriteString(fmt.Sprintf("Rule: `%s`\n\n", rule.ID))
	b.WriteString(fmt.Sprintf("Title: %s\n\n", rule.Title))
	b.WriteString(fmt.Sprintf("Severity: %s\n\n", rule.Severity))
	b.WriteString(fmt.Sprintf("Candidate: `%s` in `%s:%d`\n\n", ev.Candidate.Expression, ev.Candidate.File, ev.Candidate.Line))
	b.WriteString("## Rule Intent\n\n")
	b.WriteString(rule.Description)
	b.WriteString("\n\n## Static Verdict\n\n")
	b.WriteString(finding.Message)
	b.WriteString("\n\n## Missing Checks\n\n")
	for _, missing := range finding.MissingChecks {
		b.WriteString(fmt.Sprintf("- `%s`\n", missing))
	}
	if len(finding.MissingChecks) == 0 {
		b.WriteString("- none\n")
	}
	b.WriteString("\n## Observed Checks\n\n")
	for _, check := range ev.Checks {
		fields := ""
		if len(check.Fields) > 0 {
			fields = fmt.Sprintf(" [fields: %s]", strings.Join(check.Fields, ", "))
		}
		b.WriteString(fmt.Sprintf("- `%s` at `%s:%d`: `%s`%s (dominates target: %t)\n", check.Kind, check.File, check.Line, check.Expression, fields, check.DominatesTarget))
	}
	if len(ev.Checks) == 0 {
		b.WriteString("- none\n")
	}
	if len(ev.KeySites) > 0 {
		b.WriteString("\n## Key Sites\n\n")
		for _, site := range ev.KeySites {
			if site.Expression != "" {
				b.WriteString(fmt.Sprintf("- `%s` at `%s:%d`: `%s`\n", site.Kind, site.File, site.Line, site.Expression))
				continue
			}
			b.WriteString(fmt.Sprintf("- `%s` at `%s:%d`\n", site.Kind, site.File, site.Line))
		}
	}
	b.WriteString("\n## Control-Flow Summary\n\n")
	for _, item := range ev.ControlFlowSummary {
		b.WriteString(fmt.Sprintf("- %s\n", item))
	}
	b.WriteString("\n## Data-Flow Summary\n\n")
	for _, item := range ev.DataFlowSummary {
		b.WriteString(fmt.Sprintf("- %s\n", item))
	}
	b.WriteString("\n## Code Snippets\n\n")
	for _, snippet := range ev.CodeSnippets {
		b.WriteString(fmt.Sprintf("### %s\n\n", snippet.Label))
		b.WriteString(fmt.Sprintf("`%s:%d`\n\n", snippet.File, snippet.Line))
		b.WriteString("```c\n")
		b.WriteString(snippet.Code)
		if !strings.HasSuffix(snippet.Code, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("```\n\n")
	}
	b.WriteString("## Review Question\n\n")
	if len(rule.LLMReviewQuestions) == 0 {
		b.WriteString("Does this evidence indicate a real TEE usage issue, or is there an implicit validation path that the static rule failed to prove?\n")
	} else {
		for _, question := range rule.LLMReviewQuestions {
			b.WriteString(fmt.Sprintf("- %s\n", question))
		}
	}

	path := filepath.Join(dir, fmt.Sprintf("%s.md", finding.ID))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
