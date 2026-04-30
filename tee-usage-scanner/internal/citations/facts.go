package citations

import (
	"fmt"
	"strings"
)

// ResolveFacts iterates over the LLM-produced cited facts, resolves
// each citation against the repo, and returns the cleaned list.
//
// Strict semantics (V1.1.2 polish, was lenient):
//   - if EVERY citation on a fact resolves, the fact is kept with
//     all citations populated → caller will mirror text into the
//     validated supporting-facts surface
//   - if ANY citation on a fact fails to resolve, the fact's
//     entire Cited slice is cleared → the fact becomes unanchored
//     and the caller will NOT mirror it into validated text
//   - facts that started with no citations stay with empty Cited
//
// Why strict: the lenient policy ("any survivor → mirror as
// validated") let a partial-failure ("X is true because of A AND B"
// where B drifted) silently land in SupportingFacts as if both
// A and B still held. The verifier and arbiter then read the
// claim as fully validated. Strict policy aligns FlattenFacts with
// ValidateFacts (which already treats partial-failure as stale)
// and removes the silent contract violation.
//
// Returns the cleaned facts and a side-channel slice of resolution
// errors for telemetry / logging. The error slice is informational;
// callers do NOT abort on resolution failure.
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
		anyFailed := false
		for _, c := range f.Cited {
			resolved, err := Resolve(c, repoRoot)
			if err != nil {
				anyFailed = true
				resolveErrors = append(resolveErrors, fmt.Sprintf("%s:%d-%d: %v",
					c.File, c.StartLine, c.EndLine, err))
				continue
			}
			kept = append(kept, resolved)
		}
		// Strict downgrade: any partial failure clears all Cited.
		// The fact text survives as an unanchored claim; consumers
		// must not treat it as validated.
		if anyFailed {
			kept = nil
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
