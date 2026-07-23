/**
 * TestScope.qll (Rust)
 *
 * Heuristics for detecting test-only or example-only code paths.
 *
 * Provides module `TestScope` with:
 *   - isTestOnlyPath(DataFlow::Node n)
 *   - isExampleOnlyPath(DataFlow::Node n)
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.internal.PathResolution
import common.GeneratedTrustFacts
import common.Control

module TestScope {
  /**
   * Holds if `n` lives in a `*_test.rs` / `_test.rs` file, under a `test`/
   * `tests` directory, OR in a function annotated `#[test]` / `#[tokio::test]` /
   * `#[async_std::test]` etc. (the unqualified attribute name is `test`). The
   * attribute arm catches inline test functions in production-path files that
   * path heuristics miss — robust across repos regardless of directory layout.
   */
  predicate isTestOnlyPath(DataFlow::Node n) {
    n.getLocation().getFile().getBaseName().matches("%_test.rs")
    or
    n.getLocation().getFile().getRelativePath().matches("%/test/%")
    or
    n.getLocation().getFile().getRelativePath().matches("%/tests/%")
    or
    isTestAnnotated(n)
    or
    GeneratedTrustFacts::hasSuppressor(n, "test_only")
  }

  /**
   * Holds if `n`'s enclosing callable carries a test-harness attribute. Matched
   * by the attribute path's UNQUALIFIED last segment (rust-all's own convention),
   * so it covers `#[test]`, `#[tokio::test]`, `#[async_std::test]`,
   * `#[rstest::test]`, etc. — any attribute whose final segment is `test`.
   */
  predicate isTestAnnotated(DataFlow::Node n) {
    exists(Function f, Attr a |
      Control::callableOf(n) = f and a = f.getAnAttr() and
      a.getMeta().getPath().(PathExt).isUnqualified("test")
    )
  }

  /**
   * Holds if `n` lives under an `example`/`examples`/`demo`/`samples` directory,
   * OR in a sample/fixture/test-generator BINARY (convention-named files such as
   * `generate_all_samples.rs`, `generate_fixtures.rs`, `test_case.rs`,
   * `test_harness.rs` under `src/bin/` or `cli/`). These are test/sample tooling,
   * not production trust paths.
   */
  predicate isExampleOnlyPath(DataFlow::Node n) {
    n.getLocation().getFile().getRelativePath().matches("%/example%/%")
    or
    n.getLocation().getFile().getRelativePath().matches("%/demo/%")
    or
    n.getLocation().getFile().getRelativePath().matches("%/samples/%")
    or
    n.getLocation().getFile().getBaseName().matches("%generate%sample%")
    or
    n.getLocation().getFile().getBaseName().matches("%generate%fixture%")
    or
    n.getLocation().getFile().getBaseName().matches("%test_case%")
    or
    n.getLocation().getFile().getBaseName().matches("%test_harness%")
    or
    GeneratedTrustFacts::hasSuppressor(n, "example_only")
  }

  /** Convenience: `n` is in PRODUCTION scope (neither test-only nor example-only). */
  predicate isInProductionScope(DataFlow::Node n) {
    not isTestOnlyPath(n) and
    not isExampleOnlyPath(n)
  }
}
