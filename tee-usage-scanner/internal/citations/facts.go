package citations

import (
	"fmt"
	"strings"
)

// ResolveFacts iterates over the LLM-produced cited facts, resolves
// each citation against the repo, drops citations that fail, and
// returns the cleaned list. Facts that lose ALL their citations
// stay in the result with an empty Cited slice — the caller decides
// how to surface "asserted but unanchored" claims.
//
// Returns the cleaned facts and a side-channel slice of resolution
// errors for telemetry / logging. The error slice is informational;
// callers do NOT abort on resolution failure.
//
// Originally lived in internal/expert as an unexported helper
// (resolveCitedFacts) — moved here so the verifier can use the
// same primitive without code duplication.
func ResolveFacts(in []CitedFact, repoRoot string) (out []CitedFact, resolveErrors []string) {
	if len(in) == 0 {
		return nil, nil
	}
	out = make([]CitedFact, 0, len(in))
	for _, f := range in {
		text := strings.TrimSpace(f.Text)
		if text == "" {
			continue
		}
		var kept []CitedBytes
		for _, c := range f.Cited {
			resolved, err := Resolve(c, repoRoot)
			if err != nil {
				resolveErrors = append(resolveErrors, fmt.Sprintf("%s:%d-%d: %v",
					c.File, c.StartLine, c.EndLine, err))
				continue
			}
			kept = append(kept, resolved)
		}
		out = append(out, CitedFact{Text: text, Cited: kept})
	}
	return out, resolveErrors
}

// FlattenFacts produces the legacy fields from a structured
// cited-fact list:
//   - validatedText : text of every fact whose citations resolved
//                     cleanly. Asserted-but-unanchored facts are
//                     intentionally excluded so consumers can use
//                     these as the "validated facts" surface.
//   - pool          : union of every resolved citation across all
//                     facts, deduplicated by
//                     (file, start_byte, end_byte, sha256). Keeps
//                     legacy "Cited"-reading code working through
//                     the migration.
func FlattenFacts(facts []CitedFact) (validatedText []string, pool []CitedBytes) {
	seen := map[string]bool{}
	for _, f := range facts {
		if !f.HasValidCitation() {
			continue
		}
		validatedText = append(validatedText, f.Text)
		for _, c := range f.Cited {
			if !c.Resolved() {
				continue
			}
			key := fmt.Sprintf("%s:%d:%d:%s", c.File, c.StartByte, c.EndByte, c.SHA256)
			if seen[key] {
				continue
			}
			seen[key] = true
			pool = append(pool, c)
		}
	}
	return validatedText, pool
}
