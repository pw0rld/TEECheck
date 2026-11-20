package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

func Bind(c artifacts.CaseInvariantV2, ctx BindingContext) (artifacts.CaseInvariantV2, []Diagnostic, error) {
	out := clone(c)
	if err := validateDefinition(out); err != nil {
		return out, nil, err
	}
	if out.DefinitionHash != "" && out.DefinitionHash != DefinitionHash(out) {
		return out, nil, fmt.Errorf("contract definition hash mismatch")
	}
	if err := sameScope(out.Scope, ctx.Scope); err != nil {
		return out, nil, err
	}
	out.SchemaVersion = artifacts.SchemaVersionCaseInvariantV2
	out.DefinitionHash = DefinitionHash(out)
	if out.InvariantID == "" {
		out.InvariantID = "case-inv-" + out.DefinitionHash[:16]
	}
	out.Scope = ctx.Scope
	if out.Preconditions == nil {
		out.Preconditions = []string{}
	}
	if out.VerificationQueries == nil {
		out.VerificationQueries = []artifacts.ContractQuery{}
	}
	if out.RelatedTWEs == nil {
		out.RelatedTWEs = []string{}
	}
	if out.EvidenceRefs == nil {
		out.EvidenceRefs = []artifacts.ContractEvidenceRef{}
	}
	var diagnostics []Diagnostic
	for i, s := range out.Subjects {
		bound, err := BindSubject(s, ctx)
		if err != nil {
			if s.ContentSHA256 != "" || s.StartLine != 0 || s.EndLine != 0 || s.SymbolID != "" {
				return out, diagnostics, fmt.Errorf("provided subject anchor invalid: %w", err)
			}
			diagnostics = append(diagnostics, Diagnostic{Code: "unresolved_subject", Message: err.Error(), Subject: s.Path + "::" + s.Symbol})
			continue
		}
		out.Subjects[i] = bound
	}
	out.Grounding = "source_bound"
	if len(diagnostics) > 0 {
		out.Grounding = "unresolved"
	}
	for i, r := range out.EvidenceRefs {
		resolved, err := ResolveEvidence(r, ctx)
		if err != nil {
			return out, diagnostics, fmt.Errorf("evidence: %w", err)
		}
		out.EvidenceRefs[i] = resolved
	}
	if out.Grounding == "source_bound" {
		for _, s := range out.Subjects {
			out.EvidenceRefs = append(out.EvidenceRefs, artifacts.ContractEvidenceRef{Kind: "source", Path: s.Path, Symbol: s.Symbol, StartLine: s.StartLine, EndLine: s.EndLine, ContentSHA256: s.ContentSHA256})
		}
	}
	if err := validateSchema(out); err != nil {
		return out, diagnostics, err
	}
	return out, diagnostics, nil
}

func sameScope(actual, expected artifacts.ScannedScope) error {
	if actual.Commit != "" && expected.Commit != "" && actual.Commit != expected.Commit {
		return fmt.Errorf("contract commit %s differs from scope %s", actual.Commit, expected.Commit)
	}
	if actual.RepoURL != "" && expected.RepoURL != "" && actual.RepoURL != expected.RepoURL {
		return fmt.Errorf("contract repository differs from scope")
	}
	if actual.Hash != "" && expected.Hash != "" && actual.Hash != expected.Hash {
		return fmt.Errorf("contract scope hash differs")
	}
	return nil
}
func validateSchema(c artifacts.CaseInvariantV2) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return schema.Validate(schema.CaseInvariantV2, b)
}
func Validate(c artifacts.CaseInvariantV2, ctx BindingContext) error {
	if err := validateDefinition(c); err != nil {
		return err
	}
	if err := validateSchema(c); err != nil {
		return err
	}
	if c.DefinitionHash != DefinitionHash(c) {
		return fmt.Errorf("definition hash mismatch")
	}
	if err := sameScope(c.Scope, ctx.Scope); err != nil {
		return err
	}
	if c.Grounding != "source_bound" {
		return nil
	}
	if c.Scope.Commit == "" {
		return fmt.Errorf("bound contract has no commit")
	}
	if ctx.Scope.RepoURL != "" && c.Scope.RepoURL != ctx.Scope.RepoURL {
		return fmt.Errorf("bound contract repository mismatch")
	}
	for _, s := range c.Subjects {
		if s.ContentSHA256 == "" || s.StartLine == 0 || s.EndLine == 0 {
			return fmt.Errorf("bound subject has incomplete anchor")
		}
		if _, err := BindSubject(s, ctx); err != nil {
			return err
		}
	}
	for _, r := range c.EvidenceRefs {
		if _, err := ResolveEvidence(r, ctx); err != nil {
			return err
		}
	}
	return nil
}

// BindSubject resolves the definition afresh and never silently repairs a
// supplied stale location/hash. Re-verification must first strip old anchors.
func BindSubject(s artifacts.ContractSubject, ctx BindingContext) (artifacts.ContractSubject, error) {
	full, err := resolvePath(ctx.RepoRoot, s.Path)
	if err != nil {
		return s, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return s, err
	}
	defs := findDefinitions(string(data), s.Symbol)
	if ctx.RepoFacts != nil {
		if err := sameScope(ctx.RepoFacts.Scope, ctx.Scope); err != nil {
			return s, err
		}
		var matches []artifacts.Symbol
		for _, symbol := range ctx.RepoFacts.Symbols {
			if symbol.File == s.Path && (symbol.Name == s.Symbol || symbol.QualifiedName == s.Symbol) {
				matches = append(matches, symbol)
			}
		}
		if s.SymbolID != "" && len(matches) > 0 {
			exact := []artifacts.Symbol{}
			for _, candidate := range matches {
				if candidate.SymbolID == s.SymbolID {
					exact = append(exact, candidate)
				}
			}
			if len(exact) == 0 {
				return s, fmt.Errorf("supplied symbol identity is absent from the current index")
			}
			matches = exact
		}
		if len(matches) > 1 {
			return s, fmt.Errorf("ambiguous subject %s::%s", s.Path, s.Symbol)
		}
		if len(matches) == 1 {
			m := matches[0]
			var at []definition
			for _, d := range defs {
				if d.start <= m.StartLine && m.StartLine <= d.nameLine {
					d.id = m.SymbolID
					at = append(at, d)
				}
			}
			defs = at
		}
	}
	if len(defs) != 1 {
		return s, fmt.Errorf("subject %s::%s resolves to %d definitions", s.Path, s.Symbol, len(defs))
	}
	d := defs[0]
	if s.SymbolID != "" && d.id != "" && s.SymbolID != d.id {
		return s, fmt.Errorf("symbol identity mismatch")
	}
	if s.SymbolID != "" && d.id == "" {
		parts := strings.SplitN(string(s.SymbolID), ":", 4)
		if len(parts) != 4 || parts[1] != s.Path || !strings.HasPrefix(parts[3], s.Symbol+"(") {
			return s, fmt.Errorf("unresolvable supplied symbol identity")
		}
		var line int
		if _, err := fmt.Sscanf(parts[2], "%d", &line); err != nil || line < d.start || line > d.nameLine {
			return s, fmt.Errorf("supplied symbol line mismatch")
		}
	}
	start, end := d.start, d.end
	if s.StartLine > 0 {
		start = s.StartLine
		if start < d.start || start > d.end {
			return s, fmt.Errorf("subject start line outside definition")
		}
	}
	if s.EndLine > 0 {
		end = s.EndLine
		if end < start || end > d.end {
			return s, fmt.Errorf("subject end line outside definition")
		}
	} else if s.StartLine > 0 {
		end = start
	}
	region, err := sourceSpan(data, start, end)
	if err != nil {
		return s, err
	}
	hash := contentHash(region)
	if s.ContentSHA256 != "" && s.ContentSHA256 != hash {
		return s, fmt.Errorf("subject content hash mismatch")
	}
	s.StartLine = start
	s.EndLine = end
	s.ContentSHA256 = hash
	if d.id != "" {
		s.SymbolID = d.id
	}
	return s, nil
}

type definition struct {
	start, end, nameLine int
	id                   artifacts.SymbolID
}

// The fallback recognizes definitions rather than arbitrary name substrings.
// Ambiguous or unsupported syntax stays unresolved; an index can disambiguate.
func findDefinitions(src, symbol string) []definition {
	name := symbol
	if at := strings.Index(name, "("); at >= 0 {
		name = name[:at]
	}
	if at := strings.LastIndex(name, "::"); at >= 0 {
		name = name[at+2:]
	}
	if name == "" {
		return nil
	}
	masked := maskNonCode(src)
	rx := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
	var out []definition
	for _, loc := range rx.FindAllStringIndex(masked, -1) {
		lineStart := strings.LastIndex(masked[:loc[0]], "\n") + 1
		prefix := strings.TrimSpace(masked[lineStart:loc[0]])
		headerStart := lineStart
		if prefix == "" && lineStart > 0 {
			priorEnd := lineStart - 1
			priorStart := strings.LastIndex(masked[:priorEnd], "\n") + 1
			previous := strings.TrimSpace(masked[priorStart:priorEnd])
			if previous != "" && !strings.ContainsAny(previous, ";{}()=.") {
				prefix = previous
				headerStart = priorStart
			}
		}
		if strings.ContainsAny(prefix, ";=.") || strings.Contains(prefix, "->") {
			continue
		}
		fields := strings.Fields(prefix)
		bad := len(fields) == 0
		for _, f := range fields {
			switch f {
			case "return", "if", "while", "switch", "for", "sizeof", "case":
				bad = true
			}
		}
		if bad {
			continue
		}
		open := strings.Index(masked[loc[0]:loc[1]], "(") + loc[0]
		close := matching(masked, open, '(', ')')
		if close < 0 {
			continue
		}
		tail := close + 1
		for tail < len(masked) && (masked[tail] == ' ' || masked[tail] == '\n' || masked[tail] == '\r' || masked[tail] == '\t') {
			tail++
		}
		for tail < len(masked) && masked[tail] != '{' && masked[tail] != ';' && tail-close < 512 {
			tail++
		}
		if tail >= len(masked) || masked[tail] != '{' {
			continue
		}
		end := matching(masked, tail, '{', '}')
		if end < 0 {
			continue
		}
		out = append(out, definition{start: strings.Count(src[:headerStart], "\n") + 1, nameLine: strings.Count(src[:loc[0]], "\n") + 1, end: strings.Count(src[:end], "\n") + 1})
	}
	return out
}
func matching(s string, start int, open, close byte) int {
	depth := 0
	for i := start; i < len(s); i++ {
		if s[i] == open {
			depth++
		}
		if s[i] == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
func maskNonCode(src string) string {
	out := []byte(src)
	state := byte(0)
	for i := 0; i < len(out); i++ {
		c := src[i]
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}
		if state == 'l' {
			if c == '\n' {
				state = 0
			} else {
				out[i] = ' '
			}
			continue
		}
		if state == 'b' {
			if c != '\n' {
				out[i] = ' '
			}
			if c == '*' && next == '/' {
				out[i+1] = ' '
				i++
				state = 0
			}
			continue
		}
		if state == '"' || state == '\'' {
			if c != '\n' {
				out[i] = ' '
			}
			if c == '\\' && i+1 < len(src) {
				i++
				if src[i] != '\n' {
					out[i] = ' '
				}
				continue
			}
			if c == state {
				state = 0
			}
			continue
		}
		if c == '/' && next == '/' {
			out[i] = ' '
			out[i+1] = ' '
			i++
			state = 'l'
		} else if c == '/' && next == '*' {
			out[i] = ' '
			out[i+1] = ' '
			i++
			state = 'b'
		} else if c == '"' || c == '\'' {
			state = c
			out[i] = ' '
		}
	}
	return string(out)
}
func sourceSpan(data []byte, start, end int) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if start < 1 || end < start || end > len(lines) {
		return nil, fmt.Errorf("source range %d-%d is out of bounds", start, end)
	}
	return []byte(strings.Join(lines[start-1:end], "\n")), nil
}
func contentHash(data []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t\r")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.Join(lines, "\n"))))
	return hex.EncodeToString(sum[:])
}
