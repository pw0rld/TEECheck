package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadObligations reads every `.md` file under
// `<knowledgeRoot>/wiki/obligations/` and `<knowledgeRoot>/wiki/patterns/`
// and returns them as a single block suitable for inlining into the
// planner system prompt.
//
// The wiki pages are intentionally short (≈10 lines each) so the whole
// block fits in a few hundred tokens. Each file is emitted with a
// `### <basename>` header so the LLM sees them as discrete obligation
// entries rather than one run-on document.
//
// Returns "" if the directory does not exist or contains no readable
// .md files. The caller is expected to treat this as "no obligations
// wiki is wired up, proceed with sink catalog only".
func LoadObligations(knowledgeRoot string) string {
	if strings.TrimSpace(knowledgeRoot) == "" {
		return ""
	}
	dirs := []string{
		filepath.Join(knowledgeRoot, "wiki", "obligations"),
		filepath.Join(knowledgeRoot, "wiki", "patterns"),
	}

	var entries []string
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.md"))
		if err != nil || len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := strings.TrimSpace(string(data))
			if content == "" {
				continue
			}
			base := strings.TrimSuffix(filepath.Base(path), ".md")
			entries = append(entries, fmt.Sprintf("### %s\n%s", base, content))
		}
	}
	if len(entries) == 0 {
		return ""
	}
	return strings.Join(entries, "\n\n")
}
