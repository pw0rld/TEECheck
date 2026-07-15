/**
 * Fetch.qll (JavaScript)
 *
 * Enumeration ("fetch") helpers for the IRIS enumerate-then-classify pipeline.
 *
 * Mirrors the Go version (`../go/common/Fetch.qll`). Provides:
 *   - excludedFromEnumeration(File f)   TRUE for vendor / generated / minified / build paths.
 *   - enumerableFile(File f)            TRUE for in-scope source files (the negation).
 *   - enumerableLocation(Locatable n)   TRUE when n's location is in an enumerable file.
 *
 * Matching is done on the file's absolute path (File.getAbsolutePath() is the
 * authoritative accessor in javascript-all 2.6.20). Each deny-glob is anchored
 * on its final path segment so it matches regardless of where the repo lives
 * on disk. See the body of excludedFromEnumeration for the exact globs.
 */

import javascript

/**
 * Holds if f lives under a vendor / third-party / generated / build / test
 * path and should therefore be excluded from repo-wide API enumeration.
 */
predicate excludedFromEnumeration(File f) {
  exists(string p |
    p = f.getAbsolutePath()
  |
    // Third-party dependency trees.
    p.matches("%/node_modules/%")
    or p.matches("%/vendor/%")
    or p.matches("%/third_party/%")
    or p.matches("%/bower_components/%")
    // Minified / generated bundles.
    or p.matches("%.min.js")
    or p.matches("%/dist/%")
    or p.matches("%/build/%")
    or p.matches("%/generated/%")
    // Build artifacts.
    or p.matches("%/target/%")
    or p.matches("%/.next/%")
    or p.matches("%/out/%")
    // Test fixtures.
    or p.matches("%/testdata/%")
    or p.matches("%/fixtures/%")
    or p.matches("%/__mocks__/%")
    or p.matches("%/__fixtures__/%")
  )
}

/**
 * Holds if `f` is in scope for repo-wide enumeration: a real JavaScript source
 * file (.js / .jsx / .ts / .tsx / .mjs / .cjs) that is NOT excluded.
 */
predicate enumerableFile(File f) {
  (
    f.getBaseName().matches("%.js")
    or f.getBaseName().matches("%.jsx")
    or f.getBaseName().matches("%.ts")
    or f.getBaseName().matches("%.tsx")
    or f.getBaseName().matches("%.mjs")
    or f.getBaseName().matches("%.cjs")
  )
  and
  not excludedFromEnumeration(f)
}

/**
 * Holds if AST node `n` (anything with a Location) lives in an enumerable file.
 * Convenience predicate for queries that already hold an Expr / Stmt / Function.
 */
predicate enumerableLocation(Locatable n) {
  enumerableFile(n.getLocation().getFile())
}
