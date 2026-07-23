package codeql

import (
	"fmt"
	"path/filepath"
	"sort"
)

// RustLibrariesPath locates the vendored, fully-resolved Rust QL library set
// inside a CodeQL bundle. A custom TWE query pack depends on codeql/rust-all,
// which pulls transitive packs (codeql/namebinding and others) that a bundle
// ships only vendored under the rust-queries pack's .codeql/libraries cache,
// not as top-level installable packs. Passing this directory as the sole
// AdditionalPacks entry lets a custom query resolve `import rust` fully offline
// — no `codeql pack install`, no network, and no "found in multiple locations"
// clash (which happens if the top-level qlpacks dir is also on the path).
//
// bundleRoot is the directory containing the `codeql` binary (e.g.
// /root/codeql-home/codeql). Returns an error if no rust-queries library cache
// is found.
func RustLibrariesPath(bundleRoot string) (string, error) {
	pattern := filepath.Join(bundleRoot, "qlpacks", "codeql", "rust-queries", "*", ".codeql", "libraries")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("glob rust libraries: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no rust-queries library cache under %s (is this a CodeQL bundle with the Rust pack?)", bundleRoot)
	}
	// Multiple versions can coexist; the lexically greatest is the newest.
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}
