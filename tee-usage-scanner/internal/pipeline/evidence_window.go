package pipeline

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// The evidence window for deterministic cases.
//
// The P4+ oracle run exposed a mechanical reason its catch shipped at
// confidence "low" that had nothing to do with the CodeQL anchor: the
// case's snippets came from the generic collector (internal/cases
// collectSnippets), which includes small target files whole but windows
// large files around the FIRST textual mention of a symbol. For
// CVE-2026-44362 that showed the producer file in full while the
// rollback authority's body — the code that decides what a zero version
// means — stayed outside every window, and the produced-struct
// definitions were never candidates at all. Both follow-up queries the
// chain issued returned "insufficient evidence", and the arbiter
// honestly downgraded.
//
// This file closes that gap at the source: for a positive fact-layer
// result, resolve the DEFINITIONS of the functions the finding names and
// the structs the fact table declares (plus the structs those bodies
// reference), and slice their bodies into pack.Snippets. Function
// definitions are resolved through the run's own index
// (repo_facts.v1.json capsules) keyed by (name, path) — never by bare
// name, which the OP-TEE index alone makes ambiguous for 971 symbols —
// so a call site can never be mistaken for the definition either.
// Struct definitions are searched in the files the finding already
// touches and, when not there, across the repository's headers: produced
// structs routinely live in headers far from both the producer and the
// authority (the motivating CVE's shdr_pub_key/shdr_subkey pair lives in
// core/include/signed_hdr.h, in neither file). Everything degrades
// gracefully: a missing index, unresolvable symbol, or unfound struct
// yields fewer snippets, never an error — the structural finding itself
// is already grounded without them.

const (
	// maxFunctionSnippetLines bounds a sliced function body. A C function
	// longer than this is sliced, not skipped: the first N lines carry the
	// signature, the field reads, and usually the guard the chain needs.
	maxFunctionSnippetLines = 150
	// maxStructSnippetLines bounds a sliced struct definition the same way.
	maxStructSnippetLines = 120
	// maxEvidenceSnippets caps the total added to one pack so a finding
	// naming many sites cannot blow the expert prompt budget.
	maxEvidenceSnippets = 8
	// maxDerivedStructs bounds how many struct names extracted from the
	// sliced bodies (the consumed/input types the table does not name —
	// e.g. the motivating CVE's shdr_subkey) are looked up.
	maxDerivedStructs = 4
)

// functionDef is the definition site the run's index recorded for one
// function name. Line is the 1-indexed definition line. A name maps to a
// SLICE of sites: same-named static helpers in different files are common
// (971 names have multiple sites in the OP-TEE index), and attaching the
// wrong one is worse than attaching none.
type functionDef struct {
	File string
	Line int
}

// loadFunctionIndex reads the run's persisted repo facts (~32 MB on the
// OP-TEE corpus) and indexes every function capsule by name, keeping ALL
// definition sites per name. The caller loads it once per lane pass and
// reuses it across positive facts; with one supported operation that is
// one load, and it must not become a package singleton — a future run
// directory differs from this one. A missing or unreadable repo_facts
// file returns an empty index and no error: the enrichment is
// best-effort by contract.
func loadFunctionIndex(runDir string) map[string][]functionDef {
	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		return nil
	}
	index := make(map[string][]functionDef, len(facts.Capsules))
	for _, c := range facts.Capsules {
		if c.Name == "" || c.File == "" || c.Line <= 0 {
			continue
		}
		index[c.Name] = append(index[c.Name], functionDef{File: c.File, Line: c.Line})
	}
	return index
}

// isTopLevelClose reports whether a line closes a top-level C block: a
// "}" at column 0, optionally followed by ";" (the normal struct
// terminator) and/or a trailing comment. Indentation is significant —
// an inner "\t}" must NOT close — so only trailing content is trimmed.
func isTopLevelClose(line string) bool {
	if !strings.HasPrefix(line, "}") {
		return false
	}
	rest := strings.TrimSpace(line[1:])
	if rest == "" {
		return true
	}
	if strings.HasPrefix(rest, ";") {
		if rest = strings.TrimSpace(rest[1:]); rest == "" {
			return true
		}
	}
	return strings.HasPrefix(rest, "/*") && strings.HasSuffix(rest, "*/")
}

// sliceDefinition reads the file at rel from repoRoot and returns the
// lines [start, close] where start is the 1-indexed definition line and
// close is the first subsequent top-level close (see isTopLevelClose),
// capped at maxLines. When no close is found within the cap the slice is
// returned WITH a trailing truncation marker — a silently truncated body
// reads as complete to the chain. ok is false when the file cannot be
// read or start is out of range; callers treat that as "no snippet".
func sliceDefinition(repoRoot, rel string, start, maxLines int) (artifacts.PromptSnippet, bool) {
	data, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		return artifacts.PromptSnippet{}, false
	}
	lines := strings.Split(string(data), "\n")
	if start < 1 || start > len(lines) {
		return artifacts.PromptSnippet{}, false
	}
	end := start - 1 + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	closed := false
	for i := start; i <= end; i++ {
		if isTopLevelClose(lines[i-1]) {
			end = i
			closed = true
			break
		}
	}
	content := strings.Join(lines[start-1:end], "\n")
	if !closed {
		content += "\n/* … [no top-level close within the cap; truncated] */"
	}
	return artifacts.PromptSnippet{
		Path:      filepath.ToSlash(rel),
		StartLine: start,
		EndLine:   end,
		Content:   content,
	}, true
}

// structDefPattern matches the two textual forms a C struct definition of
// name can take at line start. Exact-name matching (struct name {) keeps
// a header-wide search precise: a prefix-named struct does not match.
func structDefPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^struct\s+` + regexp.QuoteMeta(name) + `\s*\{`)
}

// headerSuffixes are the files a whole-tree struct search considers. C
// corpora put type definitions in headers; limiting the fallback walk to
// these keeps a 3,000-file repository cheap to scan.
var headerSuffixes = map[string]bool{".h": true, ".hh": true, ".hpp": true}

// findStructDefinition locates the definition block of struct name. It
// searches the hint files first (cheap, likely), then falls back to a
// walk of the repository's headers — the motivating case's structs live
// in a header that is neither a definition file nor a target file, which
// is exactly why the hint-only search existed as a bug. ok is false when
// the struct appears nowhere; that is a missing snippet, never an error.
func findStructDefinition(repoRoot, name string, hintFiles []string) (artifacts.PromptSnippet, bool) {
	if name == "" {
		return artifacts.PromptSnippet{}, false
	}
	pattern := structDefPattern(name)
	search := func(rel string) (artifacts.PromptSnippet, bool) {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			return artifacts.PromptSnippet{}, false
		}
		loc := pattern.FindIndex(data)
		if loc == nil {
			return artifacts.PromptSnippet{}, false
		}
		start := strings.Count(string(data[:loc[0]]), "\n") + 1
		return sliceDefinition(repoRoot, rel, start, maxStructSnippetLines)
	}
	for _, rel := range hintFiles {
		if snip, ok := search(rel); ok {
			return snip, true
		}
	}
	var found artifacts.PromptSnippet
	var ok bool
	filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || ok {
			return nil
		}
		if d.IsDir() {
			// Prune excluded trees at the directory itself — but judged on
			// the path RELATIVE to repoRoot only. WalkDir yields paths
			// joined from repoRoot as given (typically absolute), and an
			// ANCESTOR named e.g. "build" must never prune the repository
			// root itself, which would silently skip the entire walk.
			if path != repoRoot {
				if rel, relErr := filepath.Rel(repoRoot, path); relErr == nil && rel != "." {
					for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
						if part == "vendor" || part == "third_party" || part == "build" || part == "test" {
							return fs.SkipDir
						}
					}
				}
			}
			return nil
		}
		if !headerSuffixes[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return nil
		}
		// Vendor and build directories are not this repository's types.
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if part == "vendor" || part == "third_party" || part == "build" || part == "test" {
				return nil
			}
		}
		if snip, hit := search(rel); hit {
			found, ok = snip, true
			return fs.SkipAll
		}
		return nil
	})
	return found, ok
}

// referencedStructNames extracts the struct type names a piece of C
// source references ("const struct shdr_subkey *subkey" → shdr_subkey).
// These are the consumed/input types the fact table does not name; the
// chain needs their definitions to judge what the producer failed to
// propagate FROM.
var referencedStructRe = regexp.MustCompile(`\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)`)

func referencedStructNames(source string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range referencedStructRe.FindAllStringSubmatch(source, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// deterministicEvidenceSnippets assembles the evidence-window enrichment
// for one positive fact: the definition bodies of the functions the
// finding names (resolved through the index by name AND, where the
// finding supplies it, path), plus the produced-struct definitions the
// fact table declares and the struct definitions those bodies reference.
// table may be nil (no FactTable value on record); the function
// enrichment alone still applies.
func deterministicEvidenceSnippets(repoRoot string, index map[string][]functionDef, fact artifacts.ToolFact, table *trustirfacts.FactTable) []artifacts.PromptSnippet {
	if repoRoot == "" {
		return nil
	}

	// Collect the distinct symbols the finding names, each with its best
	// known path (related sites carry one; the primary location carries
	// its own). Ordering follows the finding so the most relevant
	// definitions survive the cap.
	type symRef struct {
		name string
		path string
	}
	var symbols []symRef
	seen := map[string]bool{}
	add := func(name, path string) {
		name = strings.TrimSpace(name)
		path = strings.TrimSpace(path)
		if name == "" {
			return
		}
		// Dedup on (name, path): two path-qualified same-named statics
		// are different evidence targets and both resolve.
		key := name
		if path != "" {
			key = path + ":" + name
		}
		if seen[key] {
			return
		}
		seen[key] = true
		symbols = append(symbols, symRef{name: name, path: path})
	}
	if len(fact.Locations) > 0 {
		add(fact.Locations[0].Symbol, fact.Locations[0].Path)
	}
	for _, f := range fact.Findings {
		for _, rel := range f.Related {
			add(rel.Symbol, rel.Path)
		}
	}

	var snippets []artifacts.PromptSnippet
	// hintFiles for the struct search's cheap pass: every file already
	// contributing a snippet, then the pack's target files.
	var hintFiles []string
	hintSeen := map[string]bool{}
	addHint := func(rel string) {
		if rel == "" || hintSeen[rel] {
			return
		}
		hintSeen[rel] = true
		hintFiles = append(hintFiles, rel)
	}

	// resolveDefinition picks the definition site for one symbol: a site
	// matching the finding's own path wins; otherwise a unique site is
	// fine; genuine ambiguity (multiple sites, no path) yields nothing —
	// the wrong same-named body is worse than none.
	resolveDefinition := func(s symRef) (functionDef, bool) {
		defs := index[s.name]
		if len(defs) == 0 {
			return functionDef{}, false
		}
		if s.path != "" {
			for _, d := range defs {
				if d.File == s.path {
					return d, true
				}
			}
		}
		if len(defs) == 1 {
			return defs[0], true
		}
		return functionDef{}, false
	}

	var bodySource strings.Builder
	for _, sym := range symbols {
		def, ok := resolveDefinition(sym)
		if !ok {
			continue
		}
		snip, ok := sliceDefinition(repoRoot, def.File, def.Line, maxFunctionSnippetLines)
		if !ok {
			continue
		}
		snippets = append(snippets, snip)
		bodySource.WriteString(snip.Content)
		bodySource.WriteString("\n")
		addHint(def.File)
		if len(snippets) >= maxEvidenceSnippets {
			return snippets
		}
	}

	// Struct names: the table's produced types, then the struct types the
	// sliced bodies reference (the consumed side the table does not name).
	var structNames []string
	structSeen := map[string]bool{}
	addStruct := func(name string) {
		if name == "" || structSeen[name] {
			return
		}
		structSeen[name] = true
		structNames = append(structNames, name)
	}
	if table != nil {
		for _, name := range table.ProducedStructs {
			addStruct(name)
		}
	}
	for _, rel := range fact.Locations {
		addHint(rel.Path)
	}
	for _, name := range referencedStructNames(bodySource.String()) {
		addStruct(name)
	}
	// Table-named structs are always attempted; derived names are capped
	// BEFORE lookup — each attempt can cost a full header walk, and a
	// failed lookup must not buy another walk for the next name (the R2
	// perf finding: budgeting successes let many unresolved names each
	// walk the whole checkout). The table's allowance counts its DISTINCT
	// non-empty names (duplicates or blanks in a hand-registered table
	// must not inflate the derived budget), and the cap applies with a
	// nil table too — then every candidate is derived.
	tableCount := 0
	if table != nil {
		counted := map[string]bool{}
		for _, n := range table.ProducedStructs {
			n = strings.TrimSpace(n)
			if n != "" && !counted[n] {
				counted[n] = true
				tableCount++
			}
		}
	}
	attempt := structNames
	if cap := tableCount + maxDerivedStructs; len(attempt) > cap {
		attempt = attempt[:cap]
	}
	for _, name := range attempt {
		if len(snippets) >= maxEvidenceSnippets {
			break
		}
		if snip, ok := findStructDefinition(repoRoot, name, hintFiles); ok {
			snippets = append(snippets, snip)
		}
	}
	return snippets
}
