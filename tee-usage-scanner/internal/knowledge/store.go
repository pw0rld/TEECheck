package knowledge

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

type Page struct {
	Title string
	Path  string
	Tags  []string
	Body  string
}

var seedPages = map[string]string{
	filepath.Join("wiki", "obligations", "trust-boundary-revalidation.md"): `# Trust Boundary Revalidation

When data crosses from a less trusted component into a more trusted component,
validation should be repeated at the receiving boundary.

Focus points:
- caller binding
- parameter validation
- host or bridge revalidation
- secure failure on invalid input
`,
	filepath.Join("wiki", "obligations", "attestation-identity-verification.md"): `# Attestation And Identity Verification

Attestation logic should bind trust decisions to verified identity material.

Focus points:
- quote or report verification
- freshness or replay resistance
- signer or identity policy checks
- rejecting degraded paths on failure
`,
	filepath.Join("wiki", "patterns", "authorization-caller-binding.md"): `# Authorization And Caller Binding

Sensitive actions should be bound to the correct caller, principal, or session.

Focus points:
- caller identity provenance
- wrapper or helper enforcement
- role checks before privileged actions
- failure should stop execution, not downgrade it
`,
}

func EnsureLayout(root string) error {
	dirs := []string{
		filepath.Join(root, "raw", "cve"),
		filepath.Join(root, "raw", "papers"),
		filepath.Join(root, "raw", "sdk"),
		filepath.Join(root, "raw", "prior-reviews"),
		filepath.Join(root, "wiki", "obligations"),
		filepath.Join(root, "wiki", "patterns"),
		filepath.Join(root, "wiki", "apis"),
		filepath.Join(root, "wiki", "projects"),
		filepath.Join(root, "wiki", "open-questions"),
		filepath.Join(root, "learned", "true-positive"),
		filepath.Join(root, "learned", "false-positive"),
		filepath.Join(root, "learned", "review-memory"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create knowledge dir %s: %w", dir, err)
		}
	}
	for rel, content := range seedPages {
		target := filepath.Join(root, rel)
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return fmt.Errorf("seed knowledge page %s: %w", target, err)
		}
	}
	return nil
}

func LoadPages(root string) ([]Page, error) {
	var pages []Page
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		bodyBytes, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		body := string(bodyBytes)
		pages = append(pages, Page{
			Title: firstHeading(body, d.Name()),
			Path:  filepath.ToSlash(rel),
			Tags:  deriveTags(rel, body),
			Body:  body,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(pages, func(i, j int) bool {
		return pages[i].Path < pages[j].Path
	})
	return pages, nil
}

func LookupForCase(root string, pack artifacts.CasePack, limit int) ([]artifacts.KnowledgeHint, error) {
	if limit <= 0 {
		limit = 4
	}
	pages, err := LoadPages(root)
	if err != nil {
		return nil, err
	}
	type scored struct {
		hint  artifacts.KnowledgeHint
		score int
	}
	var scoredPages []scored
	keywords := collectCaseKeywords(pack)
	for _, page := range pages {
		score := 0
		var reasons []string
		for _, keyword := range keywords {
			if keyword == "" {
				continue
			}
			if containsFold(page.Path, keyword) || containsFold(page.Title, keyword) {
				score += 3
				reasons = append(reasons, "title/path match: "+keyword)
			}
			for _, tag := range page.Tags {
				if containsFold(tag, keyword) {
					score += 2
					reasons = append(reasons, "tag match: "+keyword)
					break
				}
			}
			if containsFold(page.Body, keyword) {
				score++
				reasons = append(reasons, "body match: "+keyword)
			}
		}
		if score == 0 {
			continue
		}
		scoredPages = append(scoredPages, scored{
			score: score,
			hint: artifacts.KnowledgeHint{
				Title:  page.Title,
				Path:   filepath.ToSlash(filepath.Join(root, page.Path)),
				Tags:   page.Tags,
				Reason: strings.Join(uniq(reasons), "; "),
			},
		})
	}
	sort.Slice(scoredPages, func(i, j int) bool {
		if scoredPages[i].score == scoredPages[j].score {
			return scoredPages[i].hint.Path < scoredPages[j].hint.Path
		}
		return scoredPages[i].score > scoredPages[j].score
	})
	if len(scoredPages) > limit {
		scoredPages = scoredPages[:limit]
	}
	hints := make([]artifacts.KnowledgeHint, 0, len(scoredPages))
	for _, item := range scoredPages {
		hints = append(hints, item.hint)
	}
	return hints, nil
}

func collectCaseKeywords(pack artifacts.CasePack) []string {
	var values []string
	values = append(values, pack.Category, pack.Focus)
	values = append(values, pack.ExpectedObligations...)
	values = append(values, pack.TargetSymbols...)
	values = append(values, pack.TargetFiles...)
	for _, value := range values {
		if strings.Contains(value, "attestation") || strings.Contains(value, "verify") || strings.Contains(value, "quote") {
			values = append(values, "attestation", "identity", "verify")
		}
		if strings.Contains(value, "caller") || strings.Contains(value, "auth") {
			values = append(values, "authorization", "caller", "binding")
		}
		if strings.Contains(value, "boundary") || strings.Contains(value, "bridge") || strings.Contains(value, "host") {
			values = append(values, "boundary", "revalidation", "bridge")
		}
	}
	return uniq(values)
}

func firstHeading(body, fallback string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return strings.TrimSuffix(fallback, filepath.Ext(fallback))
}

func deriveTags(relPath, body string) []string {
	parts := strings.FieldsFunc(strings.ToLower(filepath.ToSlash(relPath)), func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	bodyLower := strings.ToLower(body)
	for _, keyword := range []string{"attestation", "authorization", "boundary", "verify", "caller", "binding", "state", "key", "secret"} {
		if strings.Contains(bodyLower, keyword) {
			parts = append(parts, keyword)
		}
	}
	return uniq(parts)
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func uniq(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
