package pipeline

import (
	"regexp"
	"sort"
	"strings"
)

// identifierRE matches the shapes a question uses to name code: snake_case
// and SCREAMING_CASE symbols, CamelCase types, dotted or slashed file paths.
// A bare lowercase word is not one of these on purpose — see searchTerms.
var identifierRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:[./][A-Za-z0-9_]+)+|[A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9]*|[A-Z]{2,}[A-Z0-9_]*`)

// quotedRE matches terms the asker set apart with backticks or quotes. An
// agent writing `struct shdr` or "signed_hdr.h" is naming the thing it wants,
// and that intent should survive even when the term is a plain word.
var quotedRE = regexp.MustCompile("`([^`]{2,64})`|\"([^\"]{2,64})\"")

// searchTerms extracts what a natural-language question is actually asking
// the scanner to look for.
//
// The handler used to pass strings.Fields(question) — every word of an
// English sentence, "the" and "of" and "in" included — straight through as
// search keywords. Against a one-file fixture that returned the file, which
// was merely useless: the arbiter noted the scanner "returned only the
// already-observed contents of core/crypto/signed_hdr.c". Against the
// 3291-file checkout the same question matched most of the repository and
// produced an 80 MB answer that killed the run.
//
// Requiring an identifier shape is what makes this a search rather than a
// dragnet. A question about code names the code: shdr_load_pub_key,
// SHDR_GET_SIZE, core/kernel/ree_fs_ta.c, `struct shdr`. Prose words around
// them carry no locating power in a source tree — they match everything,
// which is the same as matching nothing.
func searchTerms(question string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = strings.Trim(strings.TrimSpace(t), ".,;:?!()[]")
		if len(t) < 3 || seen[strings.ToLower(t)] {
			return
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	for _, m := range quotedRE.FindAllStringSubmatch(question, -1) {
		for _, g := range m[1:] {
			if g != "" {
				// A quoted phrase may itself hold several identifiers
				// ("struct shdr_pub_key"); keep both the phrase's parts.
				for _, id := range identifierRE.FindAllString(g, -1) {
					add(id)
				}
				add(g)
			}
		}
	}
	for _, id := range identifierRE.FindAllString(question, -1) {
		add(id)
	}
	sort.Strings(out)
	return out
}

// noSearchableTerm is what the scanner answers when a question names nothing
// it can look for.
//
// Answering "here is the whole repository" would be worse than answering
// nothing: the asking agent cannot tell an exhaustive dump from a targeted
// result, and every byte of it displaces real evidence in the prompt. Saying
// plainly that the question was not searchable lets the asker rephrase — the
// same discipline the rest of this system applies to a tool that found
// nothing (§6.5: no match within scope is not proof of absence).
const noSearchableTerm = "No searchable code identifier in the question. " +
	"This scanner matches symbols, macros, types and file paths — name one " +
	"(for example shdr_load_pub_key, SHDR_GET_SIZE, or core/kernel/ree_fs_ta.c) " +
	"and ask again. Nothing was searched, which is not evidence about the code."
