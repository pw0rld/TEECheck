# C Fact-Table Spike — Result: PASS

**Date:** 2026-07-23
**Question (merge plan §23.7):** The 2026-07-15 C-feasibility spike proved a
CodeQL C database builds and one hand-written query judges a case. It did *not*
prove the **fact-table architecture** — a thin-shell query consuming a
`GeneratedTrustFacts.qll` populated from resolved TrustIR — works on C, and it
used libtomcrypt, not OP-TEE. This spike closes that gap before PR-05 invests
in the full 7-family C port.

**Answer:** Yes. On CVE-2026-44362 (OP-TEE subkey rollback), a thin-shell query
whose entity identity comes entirely from a hand-populated C fact table flags
the vulnerable revision and stays silent on the fixed revision. The vuln/fixed
distinction is decided by the real code structure, not by the fact table — the
table is byte-identical across both runs.

## What was verified

| Step | Result |
|---|---|
| CodeQL 2.26.0 + `cpp-all` present at `/root/codeql-home` | yes (matches the earlier spike's "toolchain present") |
| Full OP-TEE tree, `git clone @revision` + `--build-mode=none` | DB builds: relations 52 MiB, ~44s import, 313 MiB on disk |
| Key functions extracted | `shdr_load_pub_key` (core/crypto/signed_hdr.c) and `check_update_version` (core/kernel/ree_fs_ta.c) both present and queryable |
| Vulnerability confirmed in source | `shdr_load_pub_key` copies `subkey->{max_depth,name_size,uuid,algo}` into `key` but never `key->version = subkey->subkey_version`; the call site passes `pub_key.version` (default 0) to `check_update_version` |
| Fix confirmed in source | fixed revision adds exactly `key->version = subkey->subkey_version;` (signed_hdr.c:320) |

## The architecture test — the actual point of this spike

A hand-populated `GeneratedTrustFacts.qll` (cpp) records only entity identity —
no vulnerability logic — mirroring tee-audit's Rust fact table:

- `isClaimProducer(f, role)` → `shdr_load_pub_key` produces the subkey pub-key
- `rollbackVersionField(field)` → `"version"` is the rollback-relevant field
- `isRollbackAuthority(call, kind)` → `check_update_version` consumes it

A thin-shell query asks a purely structural question: does the producer actually
write the rollback field into its output? All identity comes from the fact
table; the answer comes from the code.

| Database | `RollbackVersionNotPropagated.ql` | Reverse sanity query (producer *does* write version) |
|---|---|---|
| vulnerable (`a9386bf`) | **flags** `shdr_load_pub_key` (2 rows — 2 call sites of the authority) | empty |
| fixed (`43ed01d`) | **empty** | **flags** `shdr_load_pub_key` writes `version` |

The two DBs are mirror images under both queries, so the differential is real,
not an empty-query artefact. The fact table did not change between runs.

## Why this is the right shape (and matches §6.2, not the querygen route)

The query is ~15 lines of `where` over fact-table predicates plus one shared
`writesOutputField` helper. Language coupling lives in the fact table's
predicate bodies and the helper's `Assignment`/`FieldAccess` classes — not in
per-family query templates. Adding a family is a new thin shell over the same
table, O(1) in language, which is the §6.2 argument for retiring `querygen.go`.

## What this spike did NOT cover (still PR-05's work)

- **The fact table was hand-populated.** The LLM annotation + resolver pipeline
  that emits these clauses from real TrustIR is unbuilt. This proves the
  *consumption* end (thin shell + C dataflow/structure) works; it says nothing
  about annotation quality.
- **One family, one case.** STATE/rollback only. The other six families' C
  shells and the `common/*.qll` cpp port are unproven.
- **Structural predicate, not taint.** This case is judged by "does the producer
  write the field", which is decidable structurally. Families that genuinely
  need cross-function C dataflow (FLOW, LEAK) may hit the limits the earlier
  spike flagged (`--build-mode=none` resolves macros/#ifdef to source defaults).
- **DB cost.** 313 MiB per revision here; the plan's kernel-scale cases will be
  far larger. Per-commit caching (§23.3) is a hard requirement, not a nicety.

## Artefacts

Query pack (fact table + both queries) preserved in the session scratchpad at
`spike/pack/`. Not committed to the repo: the two 313 MiB databases and the
51 MiB OP-TEE checkout are reproducible from `case.yaml`'s pinned revisions via
the build recipe above.

## Decision

The fact-table architecture is viable on C. §23.7's precondition is met: PR-05
may proceed to build the annotation→facts→thin-shell pipeline and the cpp
`common/*.qll`, starting from STATE/rollback where the differential is now
proven end to end at the query layer.
