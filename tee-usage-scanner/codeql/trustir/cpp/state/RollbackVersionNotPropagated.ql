/**
 * @name TWE-STATE-001 (C/C++): rollback version not propagated by producer
 * @description A producer that fills a claim-bearing output struct consumed
 *              by a rollback authority must write the rollback-relevant
 *              field into that output. If the producer never writes the
 *              field, the authority checks a default (zero) value and the
 *              rollback database can never advance — the guard runs but is
 *              structurally inert. This is the CVE-2026-44362 shape (OP-TEE
 *              subkey rollback): `shdr_load_pub_key` never assigns
 *              `key->version = subkey->subkey_version`, so
 *              `check_update_version` always sees version 0.
 *
 *              This is a thin shell: all entity identity (which function is
 *              the producer, which field is rollback-relevant, which call is
 *              the authority) comes from GeneratedTrustFacts. The vuln/fixed
 *              distinction is decided by whether the real code structurally
 *              contains the field write, not by the fact table — see
 *              docs/design/C-fact-table-spike.md, which proved this
 *              differential end to end (fact table byte-identical across
 *              both revisions; only the source differs).
 * @kind problem
 * @id teecheck/trustir-cpp/twe-state-001
 * @problem.severity warning
 * @tags tee
 *       trustir/twe-state-001
 */
import cpp
import common.GeneratedTrustFacts

/**
 * Holds if `producer` writes struct field `field` on the produced struct
 * through its output params.
 *
 * The struct constraint is not cosmetic. Matching on field NAME alone made
 * any assignment to any field called `field`, on any type, anywhere in the
 * producer suppress the finding — a false negative reachable by an unrelated
 * local. `producedStruct` is materialized into every run's
 * GeneratedTrustFacts.qll (ProducedStructs in internal/trustirfacts/
 * facttable.go, "shdr_pub_key" for the OP-TEE entry) and was referenced by
 * nothing, so the whole differential rested on one unqualified string
 * comparison.
 */
predicate writesOutputField(Function producer, string field) {
  exists(Assignment a, FieldAccess fa |
    a.getLValue() = fa and
    fa.getTarget().getName() = field and
    GeneratedTrustFacts::producedStruct(fa.getTarget().getDeclaringType().getName()) and
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
