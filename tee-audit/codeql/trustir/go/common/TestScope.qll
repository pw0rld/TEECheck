/**
 * TestScope.qll (Go)
 *
 * Heuristics for detecting test-only or example-only / generated code paths.
 *
 * Provides module `TestScope` with:
 *   - isTestOnlyPath(DataFlow::Node n)
 *   - isExampleOnlyPath(DataFlow::Node n)
 *   - isInProductionScope(DataFlow::Node n)
 */

import go
import common.GeneratedTrustFacts

module TestScope {
  /** Holds if `n` lives in a `_test.go` file or under a `test`/`tests` directory. */
  predicate isTestOnlyPath(DataFlow::Node n) {
    n.getFile().getBaseName().matches("%_test.go")
    or
    n.getFile().getRelativePath().matches("%/test/%")
    or
    n.getFile().getRelativePath().matches("%/tests/%")
    or
    GeneratedTrustFacts::hasSuppressor(n, "test_only")
  }

  /**
   * Holds if `n` lives under an example/demo/samples directory, or in a
   * generated test-double tree (counterfeiter `fakes/`, mocks, fixtures). These
   * are tooling/demo code, not production trust paths.
   */
  predicate isExampleOnlyPath(DataFlow::Node n) {
    n.getFile().getRelativePath().matches("%/example%/%")
    or
    n.getFile().getRelativePath().matches("%/demo/%")
    or
    n.getFile().getRelativePath().matches("%/samples/%")
    or
    n.getFile().getRelativePath().matches("%/fakes/%")
    or
    n.getFile().getRelativePath().matches("%/mocks/%")
    or
    n.getFile().getRelativePath().matches("%/fixtures/%")
    or
    n.getFile().getRelativePath().matches("%/devenv/%")
    or
    n.getFile().getRelativePath().matches("%/e2e/%")
    or
    GeneratedTrustFacts::hasSuppressor(n, "example_only")
  }

  /** Convenience: `n` is in PRODUCTION scope (neither test-only nor example/generated). */
  predicate isInProductionScope(DataFlow::Node n) {
    not isTestOnlyPath(n) and
    not isExampleOnlyPath(n)
  }
}
