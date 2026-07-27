// Package symbolcheck answers one question, in one place: does a symbol a
// model claimed to have located actually appear in the source file it named?
//
// This is deliberately NOT part of internal/citations. That package's job
// stops at proving a byte range exists and hashes consistently; "does this
// content contain X" is a project-understanding-layer question (see the
// reasoning at internal/architecture/validate.go's citedRegionContains).
//
// It exists as a shared package rather than as a few lines inlined at each
// call site because three layers need the same answer — architecture model
// validation, TWE investigation role validation, and (next) verifier
// citation validation — and this project has already been bitten once by
// two places that were supposed to agree and did not.
package symbolcheck

import (
	"os"
	"path/filepath"
	"strings"
)

// FileContainsSymbol reports whether symbol occurs as a case-insensitive
// substring anywhere in repoRoot/path. An absolute path is used as-is.
//
// Whole-file containment is intentional. It provably catches the observed
// failure — a symbol that exists nowhere in the named file — without
// introducing an arbitrary "how many lines counts as near the declared
// line" constant. The cost is that a symbol present in the file but at a
// different line than declared still passes; that trade is recorded in the
// design doc's risk section.
func FileContainsSymbol(repoRoot, path, symbol string) (bool, error) {
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(repoRoot, path)
	}
	body, err := os.ReadFile(full)
	if err != nil {
		// os.ReadFile already returns a *os.PathError whose own message
		// includes the resolved path ("open <path>: ..." / "read <path>: ...").
		// Re-wrapping with the same path here would make callers see it
		// twice; return it as-is.
		return false, err
	}
	return strings.Contains(strings.ToLower(string(body)), strings.ToLower(symbol)), nil
}
