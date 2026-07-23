/**
 * @name TWE-STATE-001 (C): rollback version not propagated by producer
 * @description A producer that fills a pub-key struct consumed by a rollback
 *              authority must write the rollback version field into its output.
 *              If the producer never writes that field, the authority checks a
 *              default (zero) version and the rollback database can never
 *              advance — the guard runs but is inert.
 *
 *              This is the §8.9 / CVE-2026-44362 shape. The query is a thin
 *              shell: all entity identity comes from GeneratedTrustFacts; the
 *              vuln/fixed distinction is decided by whether the real code
 *              structurally contains the field write, not by the fact table.
 * @kind problem
 * @id teecheck/trustir-cpp/twe-state-001
 * @problem.severity warning
 * @tags tee trustir/twe-state-001
 */
import cpp
import GeneratedTrustFacts

/** Holds if `producer` writes struct field `field` through its output params. */
predicate writesOutputField(Function producer, string field) {
  exists(Assignment a, FieldAccess fa |
    a.getLValue() = fa and
    fa.getTarget().getName() = field and
    fa.getEnclosingFunction() = producer
  )
}

from Function producer, string role, string field, FunctionCall auth, string kind
where
  GeneratedTrustFacts::isClaimProducer(producer, role) and
  GeneratedTrustFacts::rollbackVersionField(field) and
  GeneratedTrustFacts::isRollbackAuthority(auth, kind) and
  not writesOutputField(producer, field)
select producer,
  "TWE-STATE-001: producer $@ never propagates rollback field '" + field +
  "'; authority $@ (" + kind + ") therefore checks a default version.",
  producer, producer.getName(), auth, auth.getTarget().getName()
