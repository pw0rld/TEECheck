/**
 * TestScope.qll (JavaScript)
 *
 * Heuristics for detecting test-only, example-only, or mock-only code paths in
 * JavaScript/TypeScript projects.
 *
 * Provides module `TestScope` with:
 *   - isTestOnlyPath(DataFlow::Node n)
 *   - isExampleOnlyPath(DataFlow::Node n)
 */

import javascript
import common.GeneratedTrustFacts

module TestScope {
  /**
   * Holds if `n` lives in a JavaScript test file or under a test directory.
   * Heuristics: `*.test.*`, `*.spec.*` base names; `test/`, `tests/`, `__tests__`
   * path segments.
   */
  predicate isTestOnlyPath(DataFlow::Node n) {
    n.getFile().getBaseName().matches("%.test.%")
    or
    n.getFile().getBaseName().matches("%.spec.%")
    or
    n.getFile().getRelativePath().matches("%/test/%")
    or
    n.getFile().getRelativePath().matches("%/tests/%")
    or
    n.getFile().getRelativePath().matches("%/__tests__/%")
    or
    GeneratedTrustFacts::hasSuppressor(n, "test_only")
  }

  /**
   * Holds if `n` lives under an `example`/`examples`/`demo`/`mock` directory.
   */
  predicate isExampleOnlyPath(DataFlow::Node n) {
    n.getFile().getRelativePath().matches("%/example%/%")
    or
    n.getFile().getRelativePath().matches("%/demo/%")
    or
    n.getFile().getRelativePath().matches("%/demos/%")
    or
    n.getFile().getRelativePath().matches("%/samples/%")
    or
    n.getFile().getRelativePath().matches("%/mock/%")
    or
    n.getFile().getRelativePath().matches("%/mocks/%")
    or
    n.getFile().getRelativePath().matches("%/__mocks__/%")
    or
    GeneratedTrustFacts::hasSuppressor(n, "example_only")
  }
}
