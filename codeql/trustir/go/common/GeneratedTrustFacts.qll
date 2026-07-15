/**
 * GeneratedTrustFacts.qll (iteration 2) — GENERATED from resolved annotations.
 * Language: go. Name-based facts (no exact-line anchors). FACTS ONLY.
 */
import go

module GeneratedTrustFacts {
  predicate isClaimField(DataFlow::Node n, string role) { none()  }
  predicate isAuthorityPoint(DataFlow::Node n, string kind) {
    (
      kind = "runtime_key_acceptance" and
      exists(DataFlow::CallNode c | c.getTarget().(Method).hasQualifiedName("github.com/x/confidential","Server","Accept") and n = c)
    )
  }
  predicate isAuthoritySubject(DataFlow::Node n, string role) {
    (
      role = "encryption_key" and
      exists(Function f, Parameter p | f.(Method).hasQualifiedName("github.com/x/confidential","Server","Accept") and p = f.getAParameter() and p.getName() = "key" and n.asParameter() = p)
    )
  }
  predicate isTrustSource(DataFlow::Node n, string role) {
    (
      role = "host_input" and
      exists(Function f, Parameter p | f.(Method).hasQualifiedName("github.com/x/confidential","Server","Handle") and p = f.getAParameter() and p.getName() = "ctx" and n.asParameter() = p)
    )
  }
  predicate isTrustSink(DataFlow::Node n, string role) {
    (
      role = "enclave_call_input" and
      exists(DataFlow::CallNode c | c.getTarget().(Method).hasQualifiedName("github.com/x/confidential","ConfidentialEthBackend","Call") and n = c.getArgument(0))
    )
  }
  predicate hasSuppressor(DataFlow::Node n, string suppressor) {
    (
      suppressor = "nonce_freshness_check" and
      exists(DataFlow::CallNode c | c.getTarget().getName() = "Accept" and n = c)
    )
  }
  predicate isAdditionalTrustFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode c |
      c.getTarget().getName() = "Wrap" and
      pred = c.getAnArgument() and succ = c
    )
  }
  predicate authoritySubjectOf(DataFlow::Node auth, DataFlow::Node subject) {
    exists(DataFlow::CallNode c, Function f, Parameter p |
      c.getTarget().(Method).hasQualifiedName("github.com/x/confidential","Server","Accept") and f.(Method).hasQualifiedName("github.com/x/confidential","Server","Accept") and
      p = f.getAParameter() and p.getName() = "key" and
      auth = c and subject.asParameter() = p
    )
  }
}
