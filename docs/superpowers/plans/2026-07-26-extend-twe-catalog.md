# 扩展 TWE 目录 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three TEECheck-local TWE catalog entries covering weakness classes the migrated tee-audit catalog misses, write the GUARD-004 playbook, and extend the leak guard to cover the catalog.

**Architecture:** `catalog.yml` gains three entries in the existing Guard/Leakage families (no new families). The leak guard is widened from playbooks-only to also scan the catalog. Then one playbook (`guard.yml`) is authored from dev-half evidence, exactly as `flow.yml` was, and measured A/B.

**Tech Stack:** YAML (catalog + playbook), Go (`internal/twe` validation, the benchmark's leak test).

## Global Constraints

- **No new families.** Reuse `Guard` and `Leakage` from `ValidFamilies`. The mismatch is at the entry level.
- **Provenance must stay separable.** `catalog.yml`'s header currently claims the file is "Migrated verbatim from tee-audit". After this change a reader — and a future maintainer merging an upstream tee-audit update — must be able to tell the 16 migrated entries from the TEECheck-local ones at a glance.
- **`enum_registry.yml` is NOT extended.** It is the single definition site shared by the LLM annotation prompt and the query layer; extending it reaches into the unbuilt fact layer. `required_trustir` is not validated against it, so new roles are allowed — but any role not in the registry must be flagged in a comment.
- **No `.ql` files are written.** `query_modules` may name a planned module; `Definition.Validate` deliberately does not require it to exist on disk.
- **Holdout stays unread.** The 21 cases in `teecheck-benchmark/datasets/split.v1.json`'s `holdout` array — their patches, oracles and sources — must not be opened while defining entries or authoring the playbook.
- **Class-level only** in `look_for` / `required_evidence`; dev-set API names may appear only as illustrative examples in `scenario` / `common_defenses`.
- `go build ./...` and `go test ./...` green in both modules (except the pre-existing `internal/collabrun` live-endpoint failures).

**The three entries (ids verified legal against `^TWE-[A-Z0-9-]+$` and non-colliding — existing run to GUARD-003 and LEAK-002):**

| id | family | name | dev-half grounding |
|---|---|---|---|
| `TWE-GUARD-004` | Guard | Incomplete Cryptographic Verification | truncated ChaCha20-Poly1305 tag comparison; ECDH public point not validated against the selected curve |
| `TWE-LEAK-003` | Leakage | Secret-Dependent Timing Observable | RSA-OAEP invalid label hash timing; RSA PKCS#1 v1.5 decryption timing |
| `TWE-LEAK-004` | Leakage | Residual or Uninitialized Memory Crosses a Boundary | over-sized memory-pool allocation left uncleared; FPU extended state at enclave entry; host-controlled iovec lengths |

---

## Task 1: Add the three catalog entries

**Files:**
- Modify: `tee-usage-scanner/knowledge/twe/definitions/catalog.yml`
- Test: `tee-usage-scanner/internal/twe/definitions_test.go` (add to existing)

**Interfaces:**
- Produces: catalog ids `TWE-GUARD-004`, `TWE-LEAK-003`, `TWE-LEAK-004`, loadable via the existing `twe` package loader.

- [ ] **Step 1: Write the failing test**

Read `internal/twe/definitions_test.go` first and follow its existing style for loading the shipped catalog. Add:

```go
// The migrated tee-audit catalog is attestation-centric; these three entries
// are TEECheck-local additions covering weakness classes the benchmark
// actually contains. The test pins their identity so a future upstream merge
// cannot silently drop them.
func TestCatalogCarriesLocalExtensions(t *testing.T) {
	defs, err := LoadDefinitions(<the shipped catalog path this file's other tests use>)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	byID := map[string]Definition{}
	for _, d := range defs {
		byID[d.ID] = d
	}
	for id, wantFamily := range map[string]Family{
		"TWE-GUARD-004": FamilyGuard,
		"TWE-LEAK-003":  FamilyLeakage,
		"TWE-LEAK-004":  FamilyLeakage,
	} {
		d, ok := byID[id]
		if !ok {
			t.Errorf("%s missing from the shipped catalog", id)
			continue
		}
		if d.Family != wantFamily {
			t.Errorf("%s family = %q, want %q", id, d.Family, wantFamily)
		}
		if d.Name == "" {
			t.Errorf("%s has no name", id)
		}
		if err := d.Validate(); err != nil {
			t.Errorf("%s fails validation: %v", id, err)
		}
	}
	// The 16 migrated entries must still be present — this change adds, never replaces.
	if len(defs) != 19 {
		t.Errorf("catalog has %d entries, want 19 (16 migrated + 3 local)", len(defs))
	}
}
```
(Check the loader's actual exported name and signature in `internal/twe/definitions.go` — the test above assumes `LoadDefinitions(path)`; use whatever the package really exposes, as the other tests in the file do.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/twe/ -run TestCatalogCarriesLocalExtensions -v`
Expected: FAIL — the three ids are missing and the count is 16.

- [ ] **Step 3: Add the entries and rewrite the header**

In `catalog.yml`, replace the first line of the header so provenance is explicit. The current first two lines read:
```
# Migrated verbatim from tee-audit's trustir/spec/twe_catalog.yml (PR-02 of
# the TEECheck/tee-audit merge, docs/TEECHECK_TEE_AUDIT_MERGE.zh-CN.md §20.1).
```
Change them to state that the first 16 entries are the verbatim migration and that entries below the marked section are TEECheck-local, added because the migrated catalog is attestation-centric while this project's corpus is OP-TEE/TF-M kernel CVEs. Keep the rest of the existing header intact.

Append the three entries at the end of the `twe:` list, preceded by a clear section marker comment, e.g.:

```yaml
  # ── TEECheck-local extensions ─────────────────────────────────────────
  # The entries above are tee-audit's, migrated verbatim. Everything below
  # was added by TEECheck because the migrated catalog is attestation-centric
  # and has no entry for these classes, each of which the benchmark corpus
  # actually contains. Each entry records the dev-half CVEs it generalizes.
  # Keep this boundary intact: a future upstream catalog update must be able
  # to replace the block above without touching these.

  # Generalizes: truncated ChaCha20-Poly1305 tag comparison (CWE-187);
  # ECDH public point not validated against the selected curve (CWE-347).
  # query_modules names a planned module; the query does not exist yet.
  # NOTE: none of these roles exist in enum_registry.yml yet.
  - id: TWE-GUARD-004
    family: Guard
    name: Incomplete Cryptographic Verification
    query_modules: [guard/IncompleteCryptographicVerification.ql]
    required_trustir: [verification_operation, verified_input_span, accepted_domain_constraint, authority_point]
```

Write the other two the same way (section comment naming their dev-half grounding, a note that `query_modules` is planned, and a note for any `required_trustir` role absent from `enum_registry.yml`):
- `TWE-LEAK-003` / Leakage / `Secret-Dependent Timing Observable` / `query_modules: [leakage/SecretDependentTiming.ql]`
- `TWE-LEAK-004` / Leakage / `Residual or Uninitialized Memory Crosses a Boundary` / `query_modules: [leakage/ResidualMemoryCrossesBoundary.ql]`

For `required_trustir` on those two, prefer terms that already exist in `knowledge/twe/definitions/enum_registry.yml` (read it — `observable_sink_role`, `trust_sink_role`, `state_object_kind` are the plausible categories). Use a new role name only where the registry genuinely has no fit, and flag it in the comment. Do not edit `enum_registry.yml`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/twe/ ./internal/twecontext/ ./internal/preprocessor/ -v`
Expected: PASS. If another test asserts the catalog has exactly 16 entries, update it to 19 with a comment explaining the split — do not delete the assertion.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/knowledge/twe/definitions/catalog.yml tee-usage-scanner/internal/twe/definitions_test.go
git commit -m "knowledge: add three TEECheck-local TWE entries for OP-TEE weakness classes"
```

---

## Task 2: Widen the leak guard to the catalog

**Files:**
- Modify: `teecheck-benchmark/evaluator/runner/leakage_test.go`

**Interfaces:**
- Consumes: `teecheck-benchmark/datasets/split.v1.json`.

- [ ] **Step 1: Write the failing check**

The existing `TestPlaybooksDoNotLeakHoldoutCases` scans only `../../../tee-usage-scanner/knowledge/twe/playbooks` (see its `playbookDir` variable). A catalog entry's `name` can leak a holdout case's identity just as a playbook can, and the catalog is not scanned today.

Refactor so the same forbidden-vocabulary check runs over **both** the playbook directory and `../../../tee-usage-scanner/knowledge/twe/definitions/catalog.yml`. Keep the existing behavior intact: the forbidden set is still built from each holdout case's CVE id, its oracle's `primary_file` (plus base name), and its `primary_function` recovered at runtime from `c3e3e28^` via git; the test still fails if zero function names could be recovered.

Extract the per-file scan into a small helper so both call sites share it rather than duplicating the loop. Rename the test to reflect the wider scope (e.g. `TestKnowledgeDoesNotLeakHoldoutCases`) or add a second test — your choice, but the catalog must be covered and the existing playbook coverage must not regress.

- [ ] **Step 2: Run it**

Run: `cd teecheck-benchmark && go test ./evaluator/runner/ -run 'Leak' -v`
Expected: PASS against the current catalog and playbooks.

- [ ] **Step 3: Prove the new coverage fires**

Temporarily append a holdout case's `primary_file` base name into a `name:` field in `catalog.yml`, re-run, confirm the test FAILS **and names both the catalog file and the owning case**, then revert and confirm PASS. Paste both outputs into your report. Confirm `git status` shows `catalog.yml` unmodified before committing. A widened guard that was never seen to fire on its new target is not widened.

- [ ] **Step 4: Commit**

```bash
git add teecheck-benchmark/evaluator/runner/leakage_test.go
git commit -m "benchmark: extend the holdout leak guard to the TWE catalog"
```

---

## Task 3: Author `guard.yml` (TWE-GUARD-004)

**Files:**
- Create: `tee-usage-scanner/knowledge/twe/playbooks/guard.yml`
- Test: `tee-usage-scanner/internal/twecontext/context_test.go` (add a shipped-playbook guard)

**Interfaces:**
- Consumes: the `TWE-GUARD-004` catalog entry (Task 1) and the widened leak guard (Task 2).

- [ ] **Step 1: Read the sources — dev-half only**

1. `tee-usage-scanner/knowledge/twe/playbooks/flow.yml` and `rollback.yml` — the two shipped playbooks; match their field semantics and abstraction level.
2. `tee-usage-scanner/knowledge/twe/definitions/enum_registry.yml` — `guard_kind`, `authority_kind`, `claim_field_role` are the relevant categories. Note `guard_kind`'s 15 terms are entirely attestation-shaped, so several entries will have no registry term; source those from the patches instead and say so.
3. tee-audit's Guard queries under `tee-audit/codeql/trustir/rust/guard/` — `isBarrier`/guard predicates encode what counts as a satisfied check.
4. **Only these two dev Guard cases**: `CVE-2023-40271` (truncated ChaCha20-Poly1305 tag comparison) and `CVE-2026-45614` (ECDH point not on the selected curve). Read their `teecheck-benchmark/datasets/<ID>/patches/fix.patch` and `oracle.yaml`.

**Do not open any case in `teecheck-benchmark/datasets/split.v1.json`'s `holdout` array.**

- [ ] **Step 2: Write the playbook**

All 13 fields, `schema_version: teecheck.twe_playbook.v1`, `id: TWE-GUARD-004`, family and name matching the catalog entry exactly.

The shared obligation across the two dev cases: **a cryptographic verification runs, but does not cover everything it is claimed to guarantee** — either not all bytes of the value being compared, or not the domain constraints of the input being used. Write that class, not the two instances.

- ❌ `compare_all_16_bytes_of_the_poly1305_tag`
- ✅ `verification_that_compares_or_validates_only_part_of_what_it_claims_to_authenticate`

`look_for` / `required_evidence`: class-level only. `scenario` / `common_defenses` may cite a concrete API as illustration.

Budgets: brief (header + `scenario` + `look_for`) ≤250 tokens; whole block ≤3000. Note the header eats ~85 chars for a long name, as `flow.yml` found — leave room.

- [ ] **Step 3: Add the shipped-playbook guard**

`internal/twecontext/context_test.go` already has `TestShippedRollbackPlaybook` and `TestShippedFlowPlaybook`. Add `TestShippedGuardPlaybook` in the same shape: assert `TWE-GUARD-004` is in the shipped catalog, its brief is within `maxBriefContextTokens`, its detail within `maxDetailContextTokens`, and tier separation holds (a `look_for` string appears in the compiled brief; a detail-only label such as `"False positives:"` does not appear in the compiled context but does appear in `catalog.Detail("TWE-GUARD-004")`).

- [ ] **Step 4: Verify**

Run: `cd tee-usage-scanner && go test ./internal/twecontext/ ./internal/preprocessor/ -v`
Expected: PASS (a ceiling violation fails here naming the offending id).

Run: `cd teecheck-benchmark && go test ./evaluator/runner/ -run 'Leak' -v`
Expected: PASS.

Prove the new guard fires: temporarily rename `guard.yml` to `guard.yml.bak`, confirm `TestShippedGuardPlaybook` FAILS, restore, confirm PASS. Report both outputs.

- [ ] **Step 5: Self-check the sourcing**

For every entry in `look_for`, `required_evidence`, `common_defenses`, `common_false_positives`, state in your report which source it came from (enum term / `.ql` predicate / which dev CVE's patch or oracle). Delete anything you cannot attribute.

- [ ] **Step 6: Commit**

```bash
git add tee-usage-scanner/knowledge/twe/playbooks/guard.yml tee-usage-scanner/internal/twecontext/context_test.go
git commit -m "knowledge: add the TWE-GUARD-004 playbook, sourced from dev-half evidence"
```

---

## Task 4: Measure (controller runs this — needs live LLM credentials)

- [ ] **Step 1: Pick the cases**

Both dev Guard cases (`CVE-2023-40271`, `CVE-2026-45614`) and both holdout Guard cases (read the holdout ids from `split.v1.json`; do not read their oracles until scoring).

- [ ] **Step 2: Run each with and without `guard.yml`**

Same harness as the Flow measurement: a baseline knowledge-root copy with `guard.yml` removed, versus the live knowledge root. Command shape (from `tee-usage-scanner/`, after `. ./.env.local`):

```
go run ./cmd/teecheck run ../teecheck-benchmark/datasets/<ID>/vulnerable \
  --repo-url <case repository> --commit <vulnerable_revision> \
  --mode llm --focus tee --run-id <id>-<arm> --output-dir <out> \
  --knowledge-root <arm's knowledge root> --max-cases 2 --max-hotspots 4
```

- [ ] **Step 3: Score and record**

Compare candidate `paths` against each oracle's `primary_file` — **not** a substring match over the whole evidence bundle, which produced false HITs in the Flow measurement. Also record the action histogram per arm (`read_file` vs `ripgrep` vs `twe_playbook_detail` counts from `events.jsonl`), since that is what revealed the mechanism last time.

Write the results to `docs/superpowers/notes/2026-07-26-guard-playbook-measurement.md`.

- [ ] **Step 4: Verdict**

Per the spec: improvement on dev **and** comparable improvement on holdout → the playbook taught a class. Improvement on dev only → instance-level contamination, rewrite. State the n and the nondeterminism honestly: this is a smoke signal, not a measurement.

---

## Self-Review Notes (coverage vs spec)

- Spec §5 three entries with dev-half grounding → Task 1.
- Spec §3 provenance separability (header rewrite + per-entry grounding comments) → Task 1 Step 3.
- Spec §4 holdout discipline + the guard's catalog blind spot → Task 2 (widen) and the "do not open holdout" constraint in Tasks 1/3.
- Spec §6 scope (3 entries, only the GUARD-004 playbook) → Tasks 1 and 3; Leakage playbooks explicitly out of scope.
- Spec §7 acceptance 1 → Task 1; 2 → Task 1 Step 3; 3 → Task 3; 4 → Task 2; 5 → Task 3 Steps 2/5; 6 → Task 4; 7 → the verification steps in each task.
- Spec §8 non-goals (no families, no enum_registry edit, no `.ql`, no Leakage playbooks, no changes to the 16 migrated entries) are carried into this plan's Global Constraints.
