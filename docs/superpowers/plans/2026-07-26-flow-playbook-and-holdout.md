# Flow Playbook + 冻结 Holdout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze a dev/holdout split of the 44 benchmark CVEs, add a mechanical leakage guard, and write one TWE-FLOW-001 playbook sourced only from dev-half material — then measure whether it improves detection.

**Architecture:** The split lands as machine-readable JSON plus a human-readable note in `teecheck-benchmark/datasets/`. A Go test in the benchmark module greps the scanner's playbooks against the holdout cases' file names, function names, and CVE ids. The playbook itself is authored in a fresh context with access to dev-half patches only.

**Tech Stack:** Go (test), YAML (playbook), `internal/twecontext` (loader/validator already enforces the token ceilings).

## Global Constraints

- **The holdout is sacred.** The 21 holdout cases' `patches/`, `oracle.yaml`, `vulnerable/`, `fixed/` must not be read while authoring the playbook. Only case IDs may be known (the leakage check needs them).
- **Class-level only.** `look_for` and `required_evidence` must state generalizable obligations, never instance facts. Dev-set function/API names may appear only as illustrative examples in `scenario` or in the explanatory text of `common_defenses` — never in `look_for` or `required_evidence`.
- **Sourcing:** every playbook line traces to one of — `knowledge/twe/definitions/enum_registry.yml` (154 terms), tee-audit's `.ql` `isSource`/`isSink`/`isBarrier` predicates, a dev-half `fix.patch`, or a dev-half oracle's `required_evidence`/`fixed_evidence`. No content invented from model memory.
- **Budgets (already enforced by the loader):** brief ≤250 tokens (id/name/family + `scenario` + `look_for`), detail ≤3000 tokens (all 13 fields). Both fail closed.
- The playbook must use an existing TWE id from `knowledge/twe/definitions/catalog.yml`. Do not add TWE entries.
- `go build ./...` and `go test ./...` green in both modules (except the pre-existing `internal/collabrun` live-endpoint failures).

**The frozen split (computed with seed 20260724, stratified by (family, CWE)):**
- dev = 23 cases, holdout = 21 cases.
- `CVE-2019-1010292` was moved holdout→dev because its patch and oracle were displayed during design exploration.
- **dev Flow (8):** CVE-2019-1010292, CVE-2019-1010293, CVE-2019-1010295, CVE-2021-44421, CVE-2022-46152, CVE-2023-51712, CVE-2024-25742, CVE-2024-45746
- **holdout Flow (6):** CVE-2019-0876, CVE-2021-43619, CVE-2025-53022, CVE-2026-33317, CVE-2026-40257, CVE-2026-45702

---

## Task 1: Freeze the split

**Files:**
- Create: `teecheck-benchmark/datasets/split.v1.json` (machine-readable source of truth)
- Create: `teecheck-benchmark/datasets/SPLIT.md` (human-readable explanation)

**Interfaces:**
- Produces: `split.v1.json` with shape `{"schema":1, "seed":20260724, "method":"...", "dev":[ids...], "holdout":[ids...], "notes":[...]}`

- [ ] **Step 1: Write `split.v1.json`**

The full dev/holdout lists are in the plan header above and must be transcribed exactly. Structure:

```json
{
  "schema": 1,
  "seed": 20260724,
  "method": "stratified by (twe_family, cwe) with alternating start side per stratum; twe_family recovered from commit c3e3e28^ and used for stratification only, never as scoring truth",
  "frozen_at": "2026-07-26",
  "dev": ["CVE-...", "..."],
  "holdout": ["CVE-...", "..."],
  "notes": [
    "CVE-2019-1010292 was moved holdout->dev: its fix.patch and oracle.yaml were displayed during design exploration on 2026-07-24, and the 2026-07-24 end-to-end probe ran against its fixture.",
    "Holdout case material (patches, oracles, sources) must not be read while authoring playbooks."
  ]
}
```

To get the exact 23 dev + 21 holdout ids: read `docs/superpowers/specs/2026-07-24-twe-playbook-coverage-design.md` §5 for the family/CWE distribution, and recover the per-case family with:
`cd /root/pp_home/idea/TEECheck && git show c3e3e28^:teecheck-benchmark/datasets/<CASE>/oracle.yaml`
The plan header lists the Flow members of each side explicitly; the remaining cases follow the same stratification. **If you cannot reproduce the exact 23/21 partition deterministically, STOP and report BLOCKED** — do not invent a different split, since the whole point is that it is frozen and reproducible.

- [ ] **Step 2: Write `SPLIT.md`**

Human-readable, referencing `split.v1.json` as the source of truth. Must state: the seed and method, the 23/21 counts, the per-family distribution table (dev: Flow 8, Guard 2, Leakage 5, State 2, out-of-scope 6; holdout: Flow 6, Guard 2, Leakage 4, State 3, out-of-scope 6), the CVE-2019-1010292 contamination note, the discipline that holdout material is not to be read, and that the benchmark's theoretical recall ceiling is 32/44 = 73% because 12 cases are outside TWE scope.

- [ ] **Step 3: Verify counts**

Run: `cd /root/pp_home/idea/TEECheck && python3 -c "
import json; s=json.load(open('teecheck-benchmark/datasets/split.v1.json'))
d,h=set(s['dev']),set(s['holdout'])
print('dev',len(d),'holdout',len(h),'overlap',len(d&h),'total',len(d|h))
import os; all_ids={x for x in os.listdir('teecheck-benchmark/datasets') if x.startswith('CVE-')}
print('covers all:', (d|h)==all_ids, 'missing:', sorted(all_ids-(d|h)))
"`
Expected: `dev 23 holdout 21 overlap 0 total 44` and `covers all: True missing: []`

- [ ] **Step 4: Commit**

```bash
git add teecheck-benchmark/datasets/split.v1.json teecheck-benchmark/datasets/SPLIT.md
git commit -m "benchmark: freeze the dev/holdout split (23/21, seed 20260724)"
```

---

## Task 2: Mechanical leakage guard

**Files:**
- Create: `teecheck-benchmark/evaluator/runner/leakage_test.go`

**Interfaces:**
- Consumes: `teecheck-benchmark/datasets/split.v1.json` (Task 1).

- [ ] **Step 1: Write the test**

The test must fail if any playbook under `tee-usage-scanner/knowledge/twe/playbooks/` mentions a holdout case's identity. Note the module layout: the test lives in `teecheck-benchmark`, and the playbooks live in the sibling `tee-usage-scanner` module — reach them with a relative path from the test's location (`../../../tee-usage-scanner/knowledge/twe/playbooks`), the same way `main_test.go` reaches `../../datasets`.

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A playbook that names a holdout case's file, function, or CVE id has
// memorized the answer instead of stating a generalizable obligation. That
// would make the holdout measurement meaningless, so it fails the build.
func TestPlaybooksDoNotLeakHoldoutCases(t *testing.T) {
	var split struct {
		Holdout []string `json:"holdout"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "datasets", "split.v1.json"))
	if err != nil {
		t.Fatalf("read split: %v", err)
	}
	if err := json.Unmarshal(raw, &split); err != nil {
		t.Fatalf("parse split: %v", err)
	}
	if len(split.Holdout) == 0 {
		t.Fatal("split.v1.json lists no holdout cases")
	}

	// Build the forbidden vocabulary: each holdout case's id, its oracle's
	// primary_file (and that file's base name), and its primary_function.
	forbidden := map[string]string{} // term -> which case it came from
	for _, id := range split.Holdout {
		forbidden[id] = id
		oraclePath := filepath.Join("..", "..", "datasets", id, "oracle.yaml")
		data, err := os.ReadFile(oraclePath)
		if err != nil {
			continue // a case without an oracle cannot leak through it
		}
		var o struct {
			PrimaryFile     string `json:"primary_file"`
			PrimaryFunction string `json:"primary_function"`
		}
		if err := json.Unmarshal(data, &o); err != nil {
			continue
		}
		if o.PrimaryFile != "" {
			forbidden[o.PrimaryFile] = id
			if base := filepath.Base(o.PrimaryFile); base != o.PrimaryFile {
				forbidden[base] = id
			}
		}
		if o.PrimaryFunction != "" {
			forbidden[o.PrimaryFunction] = id
		}
	}

	playbookDir := filepath.Join("..", "..", "..", "tee-usage-scanner", "knowledge", "twe", "playbooks")
	entries, err := os.ReadDir(playbookDir)
	if err != nil {
		t.Fatalf("read playbook dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(playbookDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		checked++
		text := string(body)
		for term, fromCase := range forbidden {
			if term == "" {
				continue
			}
			if strings.Contains(text, term) {
				t.Errorf("%s mentions %q, which identifies holdout case %s — playbooks must state generalizable obligations, not memorized instances", e.Name(), term, fromCase)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no playbooks were checked; the path to the playbook directory is wrong")
	}
}
```

- [ ] **Step 2: Run it against the current single playbook**

Run: `cd /root/pp_home/idea/TEECheck/teecheck-benchmark && go test ./evaluator/runner/ -run TestPlaybooksDoNotLeakHoldoutCases -v`
Expected: PASS — `rollback.yml` is generic and predates the split, so it should name no holdout case. If it FAILS, read the reported term: a genuine leak means `rollback.yml` needs rewording; a false positive (e.g. a common English word appearing as a `primary_function`) means the forbidden vocabulary needs a minimum-length filter — add one (skip terms shorter than 6 characters) and note it.

- [ ] **Step 3: Prove the guard actually catches a leak**

Temporarily append a holdout case's primary function name to `tee-usage-scanner/knowledge/twe/playbooks/rollback.yml`'s `look_for` list, re-run the test, confirm it FAILS and names that case, then revert the edit and confirm it PASSES again. Report both outputs — a guard that has never been seen to fire is not a guard.

- [ ] **Step 4: Commit**

```bash
git add teecheck-benchmark/evaluator/runner/leakage_test.go
git commit -m "benchmark: fail the build when a playbook names a holdout case"
```

---

## Task 3: Author `flow.yml` (TWE-FLOW-001)

**Files:**
- Create: `tee-usage-scanner/knowledge/twe/playbooks/flow.yml`

**Interfaces:**
- Consumes: the loader/validator in `internal/twecontext` (enforces schema + both token ceilings) and the leakage test from Task 2.

- [ ] **Step 1: Read the sources — dev-half only**

Read, in this order:
1. `tee-usage-scanner/knowledge/twe/playbooks/rollback.yml` — the only existing playbook; it defines the required shape, field semantics, and the level of abstraction to match.
2. `tee-usage-scanner/knowledge/twe/definitions/catalog.yml` — confirm the exact id/name/family for TWE-FLOW-001.
3. `tee-usage-scanner/knowledge/twe/definitions/enum_registry.yml` — the 154-term fact vocabulary; `trust_source_role`, `trust_sink_role`, `guard_kind` are the relevant categories for a Flow playbook.
4. tee-audit's Flow queries — `tee-audit/codeql/trustir/rust/flow/HostToEnclaveSecurityDecision.ql` and any `common/*.qll` it imports: `isSource`, `isSink`, and especially `isBarrier`/sanitizer predicates encode what counts as a defense.
5. **The 8 dev Flow cases only**, for concrete evidence of what these bugs and their fixes look like:
   `CVE-2019-1010292, CVE-2019-1010293, CVE-2019-1010295, CVE-2021-44421, CVE-2022-46152, CVE-2023-51712, CVE-2024-25742, CVE-2024-45746`
   For each, read `teecheck-benchmark/datasets/<ID>/patches/fix.patch` and `oracle.yaml` (`trigger`, `required_evidence`, `fixed_evidence`).

**You must not open any file under the 6 holdout Flow cases** (`CVE-2019-0876, CVE-2021-43619, CVE-2025-53022, CVE-2026-33317, CVE-2026-40257, CVE-2026-45702`) **or any other holdout case listed in `teecheck-benchmark/datasets/split.v1.json`.**

- [ ] **Step 2: Write the playbook**

Create `flow.yml` with all 13 required fields (same shape as `rollback.yml`): `schema_version` (must equal `teecheck.twe_playbook.v1`), `id`, `name`, `family`, `scenario`, `attacker_capabilities`, `look_for`, `investigation_steps`, `required_evidence`, `common_defenses`, `common_false_positives`, `related_twes`, `trustir_hints`.

Abstraction rule, applied per field:
- `look_for` / `required_evidence`: **class-level only.** Write the obligation, not the instance.
  - ❌ `check_that_offs_plus_size_is_validated_against_mobj_size_in_set_rmem_param`
  - ✅ `host_supplied_subrange_accepted_without_proving_it_lies_within_the_object_its_handle_selected`
- `scenario` and `common_defenses` may cite a concrete API as an illustrative example (e.g. an overflow-checked addition before a bounds comparison), because they explain rather than direct the search.
- Generalize across the 8 dev cases: they span unaligned ranges, parameter counts, pointer alignment, array indices, and injected exceptions. The playbook should name the *shared* obligation (untrusted input must be fully validated before it reaches a memory or authority operation), not eight special cases.

Budget: brief (`scenario` + `look_for` + header) ≤250 tokens; the whole block ≤3000. The loader enforces both.

- [ ] **Step 3: Verify it loads, compiles, and does not leak**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/twecontext/ ./internal/preprocessor/ -v`
Expected: PASS (a ceiling violation fails here with the offending id named).

Run: `cd /root/pp_home/idea/TEECheck/teecheck-benchmark && go test ./evaluator/runner/ -run TestPlaybooksDoNotLeakHoldoutCases -v`
Expected: PASS.

If the brief exceeds 250 tokens, shorten `scenario` — do not move content out of `look_for`, which is what makes the brief useful for relevance judgement.

- [ ] **Step 4: Self-check the sourcing**

For each entry in `look_for`, `required_evidence`, `common_defenses`, and `common_false_positives`, state in your report which source it came from (enum registry term / `.ql` predicate / which dev CVE's patch or oracle). Any entry you cannot attribute must be removed — that is the discipline this task exists to enforce.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/knowledge/twe/playbooks/flow.yml
git commit -m "knowledge: add the TWE-FLOW-001 playbook, sourced from dev-half evidence"
```

---

## Task 4: Measure (controller runs this — needs live LLM credentials)

- [ ] **Step 1: Pick the cases**

Two dev Flow cases and two holdout Flow cases, vulnerable variant only. The point of including holdout cases is that the playbook was written without seeing them — running the scanner against them does not contaminate anything, because the scanner reads source, not oracles.

- [ ] **Step 2: Run each case with and without `flow.yml`**

For the "without" arm, point `--knowledge-root` at a copy of `knowledge/` whose `twe/playbooks/flow.yml` has been removed, so the baseline is exactly today's single-playbook behavior. Command shape (from `tee-usage-scanner/`, after `. ./.env.local`):

```
go run ./cmd/teecheck run ../teecheck-benchmark/datasets/<ID>/vulnerable \
  --repo-url https://github.com/OP-TEE/optee_os --commit <vulnerable_revision> \
  --mode llm --focus tee --run-id <id>-<arm> --output-dir <out> \
  --knowledge-root <knowledge-root-for-this-arm> --max-cases 2 --max-hotspots 4
```

- [ ] **Step 3: Record the comparison**

For each run record: candidates produced, case packs, findings, whether the planner pulled `twe_playbook_detail`, and whether the reported location matches the oracle's `primary_file`. Write the table to `docs/superpowers/notes/2026-07-26-flow-playbook-measurement.md`.

- [ ] **Step 4: State the verdict honestly**

With n=2 per arm and a nondeterministic LLM, this is a **smoke signal, not a measurement** — say so in the note. The signal worth acting on is directional: does the planner now investigate the right thing (Flow obligations rather than rollback), and does it produce candidates where it previously produced none?

Per the spec's acceptance criterion 5: improvement on dev **and** comparable improvement on holdout means the playbook taught a class. Improvement on dev only means instance-level contamination and the playbook must be rewritten.

---

## Self-Review Notes (coverage vs spec)

- Spec §5 frozen split + contamination note → Task 1.
- Spec §4 abstraction discipline, mechanical check against holdout file/function names → Task 2 (guard) + Task 3 Step 2/4 (authoring rule + attribution).
- Spec §3 sourcing (enum registry / `.ql` / dev patches / dev oracles) → Task 3 Steps 1 and 4.
- Spec §2.2 scope = Flow only, existing TWE id → Task 3 (one playbook, id from `catalog.yml`).
- Spec §6 acceptance 1 (loads/compiles within ceilings) → Task 3 Step 3; acceptance 2 (no leak) → Task 2 + Task 3 Step 3; acceptance 3 (SPLIT committed) → Task 1; acceptance 4/5 (dev and holdout improvement) → Task 4; acceptance 6 (73% ceiling stated) → Task 1 Step 2 (`SPLIT.md`); acceptance 7 (suites green) → Tasks 1-3 verification steps.
- Spec §8 residual risks (same-repo generalization, leakage-suspect, small n) → Task 4 Step 4 records the n-limitation; the other two live in the spec and `SPLIT.md`.
