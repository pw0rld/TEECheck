/**
 * Fetch.qll (Go)
 *
 * Enumeration ("fetch") helpers for the IRIS enumerate-then-classify pipeline.
 *
 * Provides:
 *   - excludedFromEnumeration(File f)   TRUE for vendor / generated / proto / build paths.
 *   - enumerableFile(File f)            TRUE for in-scope source files (the negation).
 *   - enumerableLocation(Locatable n)   TRUE when n's location is in an enumerable file.
 *
 * Matching is done on the file's absolute path (File.getAbsolutePath() is the
 * authoritative public accessor in go-all 6.0.0). Each deny-glob is anchored
 * on its final path segment so it matches regardless of where the repo lives
 * on disk. See the body of excludedFromEnumeration for the exact globs.
 */

import go

/**
 * Holds if f lives under a vendor / third-party / generated / build / test
 * path and should therefore be excluded from repo-wide API enumeration.
 */
predicate excludedFromEnumeration(File f) {
  exists(string p |
    p = f.getAbsolutePath()
  |
    // Third-party dependency trees.
    p.matches("%/vendor/%")
    or p.matches("%/third_party/%")
    or p.matches("%/node_modules/%")
    // Generated / protobuf output.
    or p.matches("%.pb.go")
    or p.matches("%_gen.go")
    or p.matches("%/generated/%")
    // Build artifacts.
    or p.matches("%/target/%")
    or p.matches("%/build/%")
    // Test fixtures.
    or p.matches("%/testdata/%")
    or p.matches("%/fixtures/%")
    // Generated test doubles (counterfeiter / mockery / mockgen).
    or p.matches("%/fakes/%")
    or p.matches("%/mocks/%")
  )
}

/**
 * Holds if `f` is in scope for repo-wide enumeration: a real source file
 * that is NOT excluded.
 */
predicate enumerableFile(File f) {
  f instanceof GoFile
  and
  not excludedFromEnumeration(f)
}

/**
 * Holds if AST node `n` (anything with a Location) lives in an enumerable file.
 * Convenience predicate for queries that already hold an Expr / Stmt / Decl.
 */
predicate enumerableLocation(Locatable n) {
  enumerableFile(n.getLocation().getFile())
}
