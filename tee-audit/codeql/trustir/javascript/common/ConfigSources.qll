/**
 * ConfigSources.qll (JavaScript)
 *
 * Conservative config / weak-mode predicates, delegating to GeneratedTrustFacts.
 *
 * Provides module `ConfigSources` with:
 *   - isConfigSource(DataFlow::Node n, string kind)
 *   - weakModeReachesAuthority(DataFlow::Node source, DataFlow::Node auth)
 */

import javascript
import common.GeneratedTrustFacts

module ConfigSources {
  /**
   * A configuration source of the given kind (e.g. "env_var", "flag", "config_file",
   * "debug_mode", "dev_key"). Delegates to the generated facts trust-source role.
   */
  predicate isConfigSource(DataFlow::Node n, string kind) {
    GeneratedTrustFacts::isTrustSource(n, "config:" + kind)
    or
    GeneratedTrustFacts::isTrustSource(n, kind)
  }

  /**
   * Holds if a (weak) config `source` reaches an authority `auth`. Conservative:
   * true if both are recorded, in the same file, OR if generated facts mark the
   * source as a trust source and the auth as an authority point.
   */
  predicate weakModeReachesAuthority(DataFlow::Node source, DataFlow::Node auth) {
    exists(string srcRole, string authKind |
      GeneratedTrustFacts::isTrustSource(source, srcRole) and
      GeneratedTrustFacts::isAuthorityPoint(auth, authKind) and
      source.getFile() = auth.getFile()
    )
  }
}
