package actions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// sourceExtensions are the file types the planner's structural actions
// (tree_sitter_outline, reverse_trace) will parse. Language-agnostic:
// adding a language is adding an extension here, not a grammar.
var sourceExtensions = map[string]bool{
	".rs": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".hpp": true, ".cxx": true, ".hh": true,
}

func isSourceFile(path string) bool {
	return sourceExtensions[strings.ToLower(filepath.Ext(path))]
}

// rustFnRe / cFnRe recognize function-definition lines. cFnRe requires
// at least one leading type token and a "(" that does not end in ";"
// (a call or prototype), and the caller excludes control keywords.
var (
	rustFnRe = regexp.MustCompile(`^(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)`)
	cFnRe    = regexp.MustCompile(`^[A-Za-z_][\w\*\s]*?[\s\*]([A-Za-z_]\w*)\s*\(`)
	// structRe recognizes type-definition lines for the outline.
	structRe  = regexp.MustCompile(`^(?:pub\s+)?(?:struct|enum|union|trait|impl)\s+([A-Za-z_]\w*)`)
	cStructRe = regexp.MustCompile(`^(?:typedef\s+)?struct\s+([A-Za-z_]\w*)`)
)

// cControlKeywords are words that look like a C function name but are
// control flow — they must never be reported as function signatures.
var cControlKeywords = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "return": true,
	"sizeof": true, "do": true, "else": true, "case": true,
}

func functionSignatureLine(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
		return "", false
	}
	// A definition line opens a body — it must contain "(" and must not
	// end in ";" (that would be a prototype/declaration or a call statement).
	// Applies to both Rust and C.
	if !strings.Contains(t, "(") || strings.HasSuffix(t, ";") {
		return "", false
	}
	if m := rustFnRe.FindStringSubmatch(t); m != nil {
		return m[1], true
	}
	if m := cFnRe.FindStringSubmatch(t); m != nil {
		name := m[1]
		// The token immediately before "name(" must not be a keyword,
		// and neither may `name` itself.
		if cControlKeywords[name] {
			return "", false
		}
		first := strings.Fields(t)
		if len(first) > 0 && cControlKeywords[first[0]] {
			return "", false
		}
		return name, true
	}
	return "", false
}

// enclosingFunctionText scans upward from targetLine (1-indexed) and
// returns the name of the nearest preceding function signature. A
// column-0 "}" encountered first means targetLine sits between
// top-level definitions, so it returns "<top-level>".
func enclosingFunctionText(source []byte, targetLine int) string {
	lines := strings.Split(string(source), "\n")
	if targetLine < 1 || targetLine > len(lines) {
		return "<top-level>"
	}
	for i := targetLine - 2; i >= 0; i-- {
		line := lines[i]
		if name, ok := functionSignatureLine(line); ok {
			return name
		}
		if len(line) > 0 && line[0] == '}' {
			return "<top-level>"
		}
	}
	return "<top-level>"
}

// textOutline emits one line per definition-looking line (functions and
// type declarations) with a 1-indexed line number and a truncated snippet.
func textOutline(source []byte) string {
	lines := strings.Split(string(source), "\n")
	var buf strings.Builder
	for i, line := range lines {
		t := strings.TrimSpace(line)
		var kind, name string
		if n, ok := functionSignatureLine(line); ok {
			kind, name = "function", n
		} else if m := structRe.FindStringSubmatch(t); m != nil {
			kind, name = "type", m[1]
		} else if m := cStructRe.FindStringSubmatch(t); m != nil {
			kind, name = "type", m[1]
		} else {
			continue
		}
		snippet := t
		if len(snippet) > 100 {
			snippet = snippet[:100] + "..."
		}
		fmt.Fprintf(&buf, "[%s %s] line %d: %s\n", kind, name, i+1, snippet)
	}
	return buf.String()
}
