package trustirfacts

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// FunctionCandidate is one distinct function-like identifier the
// enumerator found in the source tree: something that appears in a
// "name(" context (a definition, a declaration, or a call). Files records
// every file the identifier appeared in, for the annotation prompt's and a
// human reviewer's context ONLY — the resolver (resolver.go) matches
// annotations against Name alone, and no query keys on Files or any line
// number (§23.4.1: no exact-line anchoring; key on names/signatures and let
// CodeQL resolve the real AST node).
type FunctionCandidate struct {
	Name  string
	Files []string
}

// Candidates is the deterministic output of Enumerate: every symbol the
// annotation step (annotate.go) may propose a role/kind for, and every
// resolver (resolver.go) check against. It is intentionally a flat,
// name-only index — not a real AST — because building one is the "cheap
// grep pass" this package chose over parsing C with a real front end (see
// annotate.go's package doc for why).
type Candidates struct {
	// Functions are function-like identifiers (definitions, declarations,
	// and call targets alike — the enumerator does not distinguish them,
	// see Enumerate's doc comment). claim_producers and
	// rollback_authorities resolve against this set.
	Functions []FunctionCandidate

	// Fields are identifiers seen as the right-hand side of a `->` or `.`
	// member access anywhere in the tree. rollback_fields resolves against
	// this set.
	Fields []string

	// Structs are identifiers seen immediately after the `struct` keyword
	// anywhere in the tree (a definition, a forward declaration, or a
	// variable's type). produced_structs resolves against this set.
	Structs []string
}

var sourceExtensions = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true,
	".hpp": true, ".hh": true, ".hxx": true,
}

// maxCandidateFileSize skips outlier files (generated tables, vendored
// blobs) a grep pass has no business scanning in full — cheap, not
// complete, matching the rest of this enumerator's design.
const maxCandidateFileSize = 4 << 20 // 4 MiB

var (
	identCallRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\(`)
	memberRe    = regexp.MustCompile(`(?:->|\.)\s*([A-Za-z_]\w*)`)
	structTagRe = regexp.MustCompile(`\bstruct\s+([A-Za-z_]\w*)`)
)

// cKeywordDenylist excludes C/C++ keywords and control constructs that
// `identCallRe` would otherwise mistake for a function name (`if (x)`,
// `switch (x)`, `sizeof(x)`, ...). It does not need to be exhaustive: a
// leftover false positive is harmless noise in Candidates.Functions (the
// resolver only checks presence, never invents a use for an extra name),
// whereas an under-filtered denylist would make a keyword resolve
// successfully as if it were a real symbol.
var cKeywordDenylist = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "do": true,
	"else": true, "return": true, "sizeof": true, "defined": true,
	"typedef": true, "struct": true, "union": true, "enum": true,
	"case": true, "goto": true, "static_assert": true, "_Static_assert": true,
	"__attribute__": true, "asm": true, "__asm__": true, "catch": true,
}

// Enumerate walks sourceRoot for C/C++ source and header files and returns
// every candidate symbol the annotation step may name. This is the
// "enumerate candidate symbols" step §23's task description asks for,
// implemented as a cheap regex/grep pass rather than a CodeQL query or a
// real C parser:
//
//   - internal/codeql's Engine only exposes "build a database, run a
//     query" — there is no cheap "list every function/param/call" call that
//     does not require building the very database this package's caller
//     may not have built yet (and building one is the expensive,
//     disk-heavy step §23.3 requires caching). Enumeration has to work
//     before, or independent of, that build.
//   - A real C/C++ AST parser is a much larger dependency for a step whose
//     only job is "does this name exist somewhere in the tree", which a
//     name-level regex answers precisely enough — the resolver (resolver.go)
//     re-verifies correctness later against the same enumerated set, and
//     the DB-backed CodeQL thin-shell query (already built by this
//     package's deterministic skeleton) is the actual authority on
//     semantics, not this enumerator.
//
// The scan never distinguishes a function definition from a declaration or
// a call site — see FunctionCandidate's doc comment — because the
// resolver's job is symbol EXISTENCE, not semantic classification; that
// distinction is exactly what the real CodeQL query (Function vs
// FunctionCall, getEnclosingFunction, ...) makes once the fact table names
// a candidate and the thin-shell query runs against the built database.
func Enumerate(sourceRoot string) (Candidates, error) {
	funcFiles := map[string]map[string]bool{}
	fields := map[string]bool{}
	structs := map[string]bool{}

	walkErr := filepath.WalkDir(sourceRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxCandidateFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(sourceRoot, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		cleaned := stripCCommentsAndLiterals(string(data))

		for _, m := range identCallRe.FindAllStringSubmatch(cleaned, -1) {
			name := m[1]
			if cKeywordDenylist[name] {
				continue
			}
			if funcFiles[name] == nil {
				funcFiles[name] = map[string]bool{}
			}
			funcFiles[name][rel] = true
		}
		for _, m := range memberRe.FindAllStringSubmatch(cleaned, -1) {
			fields[m[1]] = true
		}
		for _, m := range structTagRe.FindAllStringSubmatch(cleaned, -1) {
			structs[m[1]] = true
		}
		return nil
	})
	if walkErr != nil {
		return Candidates{}, fmt.Errorf("trustirfacts: enumerate %s: %w", sourceRoot, walkErr)
	}

	out := Candidates{
		Fields:  sortedKeys(fields),
		Structs: sortedKeys(structs),
	}
	for name, files := range funcFiles {
		out.Functions = append(out.Functions, FunctionCandidate{Name: name, Files: sortedKeys(files)})
	}
	sort.Slice(out.Functions, func(i, j int) bool { return out.Functions[i].Name < out.Functions[j].Name })
	return out, nil
}

// stripCCommentsAndLiterals blanks out block/line comments and the
// contents of string/char literals before the regexes above run, so a
// brace, paren, or identifier-looking token that only exists inside a
// comment or a string constant never becomes a fake candidate.
func stripCCommentsAndLiterals(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				if src[i] == '\n' {
					b.WriteByte('\n')
				}
				i++
			}
			i += 2
		case c == '"':
			b.WriteByte(' ')
			i++
			for i < n && src[i] != '"' {
				if src[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			i++
		case c == '\'':
			b.WriteByte(' ')
			i++
			for i < n && src[i] != '\'' {
				if src[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
