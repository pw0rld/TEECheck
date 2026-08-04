package projectmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// purposeMaxBytes bounds the README quote. Enough for the paragraph a
// project uses to say what it is; short enough that a README with a wall of
// badges cannot displace the module list.
const purposeMaxBytes = 400

// ModuleOf is the module a repository-relative path belongs to: its
// directory, truncated to two path components.
//
// It MUST agree with moduleOf in codeql/index/cpp/Symbols.ql. The index
// assigns capsules to modules and this function counts files into them; if
// the two disagree, a module's function count and file count describe
// different sets and the ratio a reader uses to spot vendored code becomes
// meaningless.
//
// Two levels is what distinguishes core/crypto from core/kernel on OP-TEE
// while keeping lib/libmbedtls whole. Deeper fragments a module into its
// subdirectories; shallower puts all 2216 files of core/ in one bucket.
func ModuleOf(rel string) string {
	rel = strings.TrimPrefix(path.Clean(strings.ReplaceAll(rel, "\\", "/")), "./")
	parts := strings.Split(rel, "/")
	switch {
	case len(parts) >= 3:
		return parts[0] + "/" + parts[1]
	case len(parts) == 2:
		return parts[0]
	default:
		return "."
	}
}

// buildModuleCards groups the index's capsules by module and derives each
// module's dependency edges from the resolved call graph.
//
// Edges are resolved through the capsule list by SymbolID. Matching callee
// names would connect two same-named statics to each other's modules, which
// is the guess SymbolID exists to prevent.
func buildModuleCards(facts artifacts.RepoFacts, fileCounts map[string]int) []artifacts.ModuleCard {
	moduleOfSymbol := make(map[artifacts.SymbolID]string, len(facts.Capsules))
	functionCounts := map[string]int{}
	for _, c := range facts.Capsules {
		moduleOfSymbol[c.SymbolID] = c.Module
		functionCounts[c.Module]++
	}

	calls := map[string]map[string]bool{}
	calledBy := map[string]map[string]bool{}
	for _, e := range facts.CallEdges {
		from, okFrom := moduleOfSymbol[e.CallerID]
		to, okTo := moduleOfSymbol[e.CalleeID]
		// A module calling itself is not a dependency; recording it would
		// make every module depend on itself and drown the edges that mean
		// something.
		if !okFrom || !okTo || from == to {
			continue
		}
		addEdge(calls, from, to)
		addEdge(calledBy, to, from)
	}

	paths := map[string]bool{}
	for m := range functionCounts {
		paths[m] = true
	}
	for m := range fileCounts {
		paths[m] = true
	}

	out := make([]artifacts.ModuleCard, 0, len(paths))
	for p := range paths {
		out = append(out, artifacts.ModuleCard{
			Path:            p,
			FileCount:       fileCounts[p],
			FunctionCount:   functionCounts[p],
			CallsModules:    sortedKeys(calls[p]),
			CalledByModules: sortedKeys(calledBy[p]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func addEdge(m map[string]map[string]bool, from, to string) {
	if m[from] == nil {
		m[from] = map[string]bool{}
	}
	m[from][to] = true
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// capsuleBytes is what one capsule costs a page, measured the way it will be
// delivered: as JSON.
func capsuleBytes(c artifacts.FunctionCapsule) int {
	data, err := json.Marshal(c)
	if err != nil {
		return observationlimits.MaxBytes
	}
	return len(data) + 1 // the comma or newline that joins it to the next
}

func pageBytes(page []artifacts.FunctionCapsule) int {
	n := 0
	for _, c := range page {
		n += capsuleBytes(c)
	}
	return n
}

// paginate splits capsules into pages that each fit one observation.
//
// The split is on bytes, not on a fixed count: the measured capsule set has
// a median of 225 bytes and a maximum of 26 KB, so any per-page count either
// wastes most of the budget on the common case or blows it on the rare one.
//
// A capsule larger than the whole budget still gets a page of its own rather
// than being dropped. It will be truncated when it is delivered, and that
// truncation is marked — but a capsule on no page can never be reviewed at
// all, and the coverage ledger would count it as unreviewed forever.
func paginate(capsules []artifacts.FunctionCapsule) [][]artifacts.FunctionCapsule {
	var pages [][]artifacts.FunctionCapsule
	var page []artifacts.FunctionCapsule
	used := 0
	for _, c := range capsules {
		n := capsuleBytes(c)
		if len(page) > 0 && used+n > observationlimits.MaxBytes {
			pages = append(pages, page)
			page, used = nil, 0
		}
		page = append(page, c)
		used += n
	}
	if len(page) > 0 {
		pages = append(pages, page)
	}
	return pages
}

// moduleSlug turns a module path into one filesystem component.
//
// The path is appended to a hash of itself because collapsing "/" to "-"
// is not injective: a repository holding both core/crypto/… and a top-level
// core-crypto/… would give two modules the same slug, and since page
// numbering restarts per module the second module's 0.json would overwrite
// the first's. Both page references would survive in the map, each naming
// its own count, and one module's capsules would be unreachable behind a
// reference that opens and returns someone else's functions — the worse
// direction of the failure the required path field exists to prevent.
func moduleSlug(module string) string {
	sum := sha256.Sum256([]byte(module))
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '.' {
			return '-'
		}
		return r
	}, module)
	safe = strings.Trim(safe, "-")
	if safe == "" {
		safe = "root"
	}
	return safe + "-" + hex.EncodeToString(sum[:])[:8]
}

// pageRef describes a page without shipping it. Path is required by the
// schema for the reason it exists: a page reference the Planner cannot open
// is a page that does not exist.
func pageRef(module string, page, count int) artifacts.FunctionCardPageRef {
	return artifacts.FunctionCardPageRef{
		Module: module,
		Page:   page,
		Count:  count,
		Path:   path.Join(runfs.FunctionCardsRelDir, moduleSlug(module), strconv.Itoa(page)+".json"),
	}
}

// documentedPurpose quotes the repository's own README.
//
// A quote, not a summary. A summary is an inference — it would need an
// evidence state and could not be cited — while a quote is a fact about a
// file the architecture agent can point at. Heading lines and badge noise
// are skipped because they say what the project is called, not what it does.
func documentedPurpose(readme string) string {
	var b strings.Builder
	for _, line := range strings.Split(readme, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "[!") || strings.HasPrefix(trimmed, "<") {
			if b.Len() > 0 {
				break // the paragraph ended
			}
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(trimmed)
		if b.Len() >= purposeMaxBytes {
			break
		}
	}
	out := b.String()
	if len(out) > purposeMaxBytes {
		// Cut on a rune boundary. A byte slice through a multi-byte rune
		// yields invalid UTF-8, which json.Marshal rewrites to U+FFFD — and
		// this field's whole contract is that it is a verbatim quote.
		cut := purposeMaxBytes
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut] + "…"
	}
	return out
}
