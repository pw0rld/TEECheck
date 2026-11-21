# TEECheck — What to Build Next (diagram edition)

A picture-based roadmap. Each item is shown as a **modification drawn on the current
architecture** — what it adds, changes, or wires — so you can see at a glance what it
touches. Items are ordered by how much each improves TEECheck's ability to find real bugs.

> **If you read only one thing:** the pipeline works, but today it finds little. Two open questions:
> the **fact-layer** LLM step (`AnnotateFactTable`) is built but **never switched on** (item 0.1);
> and **playbook value is unmeasured** — the only A/B was voided (it ran on a disconnected delivery
> pipe, now fixed), and the team found playbooks divide by **obligation-shape, not TWE family**.
> So the first job is *measure*, then populate — not author 15 playbooks.
>
> **Already done on main** since this roadmap was first drafted: playbook→CasePack wiring (was
> 0.1's other half), tiered playbook injection (was 1.2), legacy-scanner retirement (most of 5.3),
> and the fix to the lossy CasePack-collapse that was silently dropping playbook knowledge. Those
> items are marked ✅ below.
>
> **Ceiling-raisers:** **0.1** (fact layer) and **3.1** (dynamic verification) are the confident
> ones; **1.1** (playbooks) is **conditional on the A/B** — its ★ was downgraded from 5 because
> value is unproven. The rest sharpen **precision** (0.2, 0.3, 2.x, 3.3) or improve
> **evaluation / operations** (Phases 4–5).
>
> **Run mode:** TEECheck runs a single **LLM-mode** pipeline now — the legacy non-LLM scanner was
> retired. `cmd/twescan` is a separate **LLM-assisted** entry point used by the benchmark runner,
> not a user-facing mode.

**Legend**
```
  ──▶   existing flow            ═══▶ / ◀═══   added by this item      ┄┄┄▶  currently broken/missing
  (NEW) new component             [CHG]  changed logic
  ═══════  change described below  ═══════   (inline banner for this item's modification)
  ✅ present/wired in the code today      ✗ absent from the code
  ★     expected detection gain: ★ low → ★★★★★ high.  "upper bound" = unproven estimate.
```
**The three tiers (a hard rule, never broken):** `tool facts` (machine output) →
`agent opinions` → **`human verdict`**. These rank two *different* things, so don't read the
arrow as a trust ladder: the three tiers rank **what may officially count as a real
vulnerability** (only the human verdict); *escalation* (item 3.3) ranks **evidence strength**
— and there a reproduced crash (tool fact) outweighs a self-agreeing LLM (agent opinion).

---

## The current architecture (every item modifies this)

```
                          TEECheck — current architecture (LLM mode)

 repo ──▶ ① PREP & PROFILE          ② UNDERSTAND               ③ TWE KNOWLEDGE
          repofetch · preprocessor   architecture                twecontext compiles
          repomap · repomix          invariants                  knowledge/twe/playbooks/*.yml
               │                        │    │                    (today: rollback.yml + flow.yml)
               ▼                        ▼    ▼                              │
          ProjectProfile         ArchitectureModel                             │
                                  ProjectInvariant                              │
                                    │    │                                      ▼  compiled playbook text
                                    │    └──────────────────────────▶ ④ planner system prompt
                                    ▼                                   (prompt.go:82)  ✅ wired
   ┌────────────────────────────────────────────────────────────────────────────────────────────┐
   │ ④ INVESTIGATE                                                                                │
   │                                                                                              │
   │   L3 Planner ──actions──▶ {ripgrep, read_file, tree_sitter_outline,                         │
   │   (LLM loop)               reverse_trace, fact_layer_query, done, ...}                      │
   │          │                                                                                   │
   │          │  queries ──▶  TrustIR fact layer (CodeQL / staticcheck)                           │
   │          │                     │  ┄┄┄ AnnotateFactTable (LLM step) — NO production caller    │
   │          ▼                     ▼                                                             │
   │   TWEInvestigation ──▶ cases.Build ──▶ CasePack                                             │
   │   (one per candidate bug)                │  ✅ CommonDefenses / CommonFalsePositives         │
   │                                          │      from cfg.TWEPlaybooks — now wired in prod   │
   └──────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                              │ one CasePack per candidate bug
                                              ▼
   ┌────────────────────────────────────────────────────────────────────────────────────────────┐
   │ ⑤ MULTI-AGENT REVIEW (per CasePack)                                                         │
   │   Expert ─hypothesis─▶ Challenger ─challenge─▶ Verifier ─memo─▶ Arbiter ─▶ Finding           │
   │   (roles: Expert proposes → Challenger refutes → Verifier checks → Arbiter weighs)           │
   │   agentbus: Q&A channel between agents (currently "hollow" — same model answers itself)      │
   └────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                ▼
                                    ⑥ HUMAN VERDICT  (only this officially counts as a real bug)
                                                │
                                                │  feedback
                                                ▼
                                    knowledge/wiki + knowledge/learned
                                                ▲
                                                └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                                                 (dashed loop: reused by ③, ④, Expert)
```

### Glossary

- **TWE** — TEECheck's name for its **seven-family TEE-usage bug taxonomy** (the acronym
  itself isn't expanded in the codebase; the canonical definitions live in
  `knowledge/twe/definitions/taxonomy.yml`). The seven families:
  - **Flow** — *Trust Boundary Flow:* secret/trusted/host-controlled data crosses a TEE trust boundary wrongly.
  - **Guard** — *Verification Gap:* a required TEE verification is missing, incomplete, bypassable, or misread.
  - **Binding** — *Binding Weakness:* TEE artifacts, keys, identities, or attestation reports aren't properly linked.
  - **State** — *State Continuity:* sealed state, checkpoints, epochs, or authorizations lack continuity/replay resistance.
  - **Config** — *Configuration Integrity:* build flags, debug modes, or deployment configs weaken TEE guarantees.
  - **Design** — *Design Appropriateness:* the TEE is placed incorrectly, or the claimed trust model has bypasses.
  - **Leakage** — *Output/Metadata Leakage:* observable output, errors, or metadata reveal enclave secret state.
- **Playbook** — a YAML file, one per family, telling the scanner what the attack looks like, what to search for, what a correct defense looks like, and common false alarms. Today two ship: `rollback.yml` (State) and `flow.yml` (Flow).
- **CasePack** — the bounded bundle of context for **one candidate bug**, passed through the four agents (carries the playbook's defenses/false-positives + code facts).
- **TrustIR** — the **fact layer**: immutable facts about the code extracted by tools (CodeQL/staticcheck), *not* by the LLM. ("IR" = the intermediate representation those tools produce.)
- **L3 Planner** — the LLM agent that surveys the repo via an action loop and decides which candidate bugs to open cases for (the "L3" is an internal design tier; treat it as "the planner").
- **RPMB** — Replay-Protected Memory Block: hardware-backed secure storage used as a freshness / anti-rollback anchor (recurring in the State/rollback examples).
- **dcap-qvl** — Intel's Data Center Attestation Primitives quote-verification library, a common Web3-TEE dependency (recurring in the Binding/Web3 examples).
- **Tool fact / agent opinion / human verdict** — see *three tiers* above.

---

## Phase 0 — Switch on what already exists (quick wins)

### 0.1 · Switch on the fact-layer annotation step
*effort S · ★★★★ recall (State family first) · stage ④ · (the playbook→CasePack half is ✅ done on main)*

The playbook→CasePack wiring is already live in production (`run.go` builds `cfg.TWEPlaybooks` from the loaded catalog → `CasePack.CommonDefenses`). What's still **not** switched on is the fact layer's LLM step: `AnnotateFactTable` (`annotate.go:95`) is written and tested but has **no production caller**, so the fact layer returns unannotated facts.

*Pipe history (why playbook value looked null until recently):* the playbook→agent path was itself broken — `bf9ead6` sent the experience fields down a channel no agent read, and the CasePack `absorb` silently dropped `common_defenses`/`common_false_positives`; both are fixed on main (`22350e0`). So "playbooks reach the agents" only became true recently — which is exactly why the playbook A/B was voided.

```
 ┌─ ④ INVESTIGATE (zoom) ─────────────────────────────────────────────┐
 │  ③ playbooks ──▶ cfg.TWEPlaybooks ──▶ CasePack.CommonDefenses  ✅   │  (wired on main)
 │  TrustIR ◀── AnnotateFactTable (annotate.go:95)  ┄┄┄ no prod caller │
 │             ═══════ WIRE: give it a production caller ═══════        │
 └─────────────────────────────────────────────────────────────────────┘
 today's effect once wired: State family only (the annotate step emits only State/rollback
 categories — claim_field_role, authority_kind). Other families need their own categories added.
```

### 0.2 · Tell the scanner what an attacker *cannot* do
*effort S · ★★★ precision · stage ③→④*

Each playbook already lists what an attacker *can* do. Add the missing half — what they *cannot* do — so the Expert stops proposing impossible attacks.

```
 ┌─ ③ playbook ──────────────────────────────┐
 │  attacker_capabilities    (exists)         │
 │  prohibited_capabilities  ◀═══ (NEW field) │ ═══▶ ④ CasePack → Expert
 └────────────────────────────────────────────┘         (needs a mapping; gated on 0.1)
 example (Guard): prohibit "modify enclave private memory", "forge an attestation signature",
                  "run code outside the TA entry points".
 schema: the playbook schema is closed (additionalProperties:false) → adding the field means
         bumping it to v2 and migrating rollback.yml + the schema-sync test.
```

### 0.3 · Require two passes before calling something vulnerable
*effort S · ★★★★ precision · stage ⑤*

One "is it vulnerable?" question flags everything. Ask two questions and require both.

```
 ┌─ ⑤ Arbiter (zoom) ─  [CHG] ───────────────────────────────────┐
 │  NOW:   "is it vulnerable?" ──▶ yes/no                          │
 │  ═══════ CHANGES the verdict to: ═══════                         │
 │  AFTER:  Q1  vulnerable-behavior present?  ──┐                   │
 │          Q2  fix / defense present?       ──┤                   │
 │          vulnerable  iff  Q1=yes AND Q2=no ◀┘                   │
 │          Q2=yes may come from ② Architecture/Profile too         │
 │          (HW counter / RPMB / attestation freshness = no code)   │
 └─────────────────────────────────────────────────────────────────┘
 example: a "rollback counter missing" finding → Q1=yes, but Q2=yes (an RPMB counter is present)
          → NOT vulnerable. Without Q2 that's a false alarm.
```

---

## Phase 1 — Give the scanner knowledge for the other six families

### 1.1 · Validate playbook value, then populate — by obligation-shape, not family
*effort M · ★★★ recall (downgraded from 5 — value is unproven) · stage ③*

**Before authoring more playbooks, re-run the A/B on the fixed delivery pipe.** The only playbook A/B so far was **voided** — it ran while the pipe was disconnected (`bf9ead6`) and the CasePack merge was silently dropping playbook fields (`22350e0`, now fixed). So no valid measurement exists, and `guard.yml` was withdrawn on a null result that doesn't hold. The real finding (`08e22cd`): **playbooks divide by obligation-shape, not TWE family** — Flow's obligations already covered all Guard cases. So measure first; if it helps, populate by shape.

```
 ┌─ step 1: MEASURE — do playbooks help at all? ─────────────────────┐
 │  re-run the with/without-playbook A/B on the paired 44-case corpus  │
 │  (pipe is fixed now). Question: does adding a playbook raise         │
 │  paired-pass (vuln→finding AND fixed→quiet)?                        │
 └──────────────────────────────┬─────────────────────────────────────┘
                                ▼  only if yes
 ┌─ step 2: POPULATE — by obligation-shape, NOT one-per-family ───────┐
 │  today: rollback.yml (State) + flow.yml (Flow)                       │
 │  next : group content by obligation shape                            │
 │         (Flow already covered Guard's cases — family is the wrong axis)│
 │  convert: binding.yml, config.yml (older format → playbook YAML)    │
 │  author : only the shapes the A/B shows actually help                │
 └──────────────────────────────────────────────────────────────────────┘
 do NOT blindly author one playbook per family — that's the "3 playbooks → 13 cases" estimate the
 A/B falsified. binding.yml/config.yml already exist in an older format (codeql_modules/violation_condition),
 so they're converted, not authored from scratch. A generator can draft a playbook from a seed
 {cause,trigger,behavior,fix} → playbook fields; the human reviewer fills the rest (attacker_capabilities,
 required_evidence, common_false_positives, trustir_hints, id/name/family) before it passes validation.
```

### 1.2 · Tiered playbook injection  ✅ (already implemented on main)
*was ★★★ recall enabler · stage ③*

This landed — differently than first sketched. The old single ~900-token cap is gone; `twecontext` now uses **two tiers**: a **brief** block (scenario + look_for, ~250-token per-playbook cap) injected for **all** playbooks into every agent, and a **detail** block (full method, ~3000-token cap) served **on-demand per TWE** via the planner's `twe_playbook_detail` action. Both tiers still fail-closed on overflow.

```
 ┌─ ③ twecontext (zoom) ─  ✅ landed  ───────────────────────────┐
 │  ALL playbooks ──▶ brief (scenario + look_for) ──▶ every agent │  ~250-tok/playbook cap
 │  one TWE (on demand) ──▶ detail (full method) ──▶ planner      │  ~3000-tok cap, via action
 └────────────────────────────────────────────────────────────────┘
 consequence: adding playbooks (1.1) no longer risks a hard error — the brief tier stays small.
```

### 1.3 · Retrieve relevant TEE knowledge during a scan
*effort M · ★★★ precision aid · stage ④*

No way to go from "the code I'm looking at" to "known TEE knowledge about this bug type." Add a lookup that returns abstracted knowledge, never raw code.

```
 ┌─ ④ INVESTIGATE (zoom) ────────────────────────────────┐
 │  Planner actions {...}                                 │
 │               + knowledge_lookup   ◀═══ (NEW)          │
 │                     │                                  │
 │                     ▼  keyword search                  │
 │            knowledge/wiki  (sparse today: obligations/,│
 │             patterns/)                                 │
 │                     │                                  │
 │                     ▼  returns {cause,trigger,         │
 │                        behavior,fix} — NOT raw code    │
 └───────────────────────────────────────────────────────┘
 example: a function logging to a host file → retrieve "sealed-data leak via host log" →
          {trigger: TA writes a secret to an untrusted fd; fix: seal/redact first}, no snippet.
```

### 1.4 · Remember confirmed bugs across runs
*effort M · ★★★ recall aid (cold-start) · stage ⑥→④*

Every scan starts cold. Store confirmed bug patterns and feed them to the Expert as inspiration. Only human-confirmed patterns enter the store.

```
 ┌─ ⑥ feedback ──────────────────────────────────────┐
 │  human-confirmed bug ──▶ knowledge/learned/        │
 │                         (pattern store)             │
 └───────────────────────┬────────────────────────────┘
                         │ at most one per run, substantially different
                         │ (different family, or non-overlapping code fingerprint)
                         ▼  inspiration only
 ┌─ ④ Expert ◀═══ (NEW lookup action)                 │
 │  a pattern is NOT a finding by itself (knowledge    │
 │  layer, not a tool fact)                            │
 └─────────────────────────────────────────────────────┘
 example pattern: {family: State, fingerprint: "counter field declared but never assigned
                   before the guard reads it"} → fed once to the Expert as a hint, never auto-reported.
```

### 1.5 · Mine the TEE spec for concrete scenarios
*effort M · ★★ recall aid (★ is an upper bound — see caveat) · stage ③*

Pull *must-do / may-do / more-privileged-than* statements from the TEE API spec and turn each into a scenario a playbook can anchor to.

```
 ┌─ TEE API spec (OP-TEE headers first; full GP spec is a stretch source) ─┐
 │  "TA SHALL verify TA_OpenSession params"   (specify)                     │
 └────────────────────┬─────────────────────────────────────────────────────┘
                      ▼  classify
 ┌─ ③ playbook required_evidence (existing field) ──────────────────────────┐
 │  + scenario anchored to the `params` buffer        ◀═══ (NEW scenarios)   │
 └───────────────────────────────────────────────────────────────────────────┘
 caveat: the reference method (ProtocolGuard) published no real evaluation, so ★★ is an
 upper bound, not a proven gain. Start from OP-TEE headers (the plurality of the benchmark).
```

---

## Phase 2 — Cut false alarms (so the human's queue is credible)

### 2.1 · Show the Challenger the real code lines
*effort M · ★★★ precision · stage ⑤*

Refutation happens in the abstract today. Give the Challenger the actual function lines (±4, source marked) plus per-family hints, so it refutes against real code.

```
 ┌─ ⑤ Challenger (zoom) ─  [CHG] ──────────────────────────────┐
 │  NOW:   refutes from the hypothesis text alone                │
 │  ═══════ ADD a grounded view: ═══════                         │
 │  ③ playbook.trustir_hints ──▶┐                                │
 │  enclosing-fn lines (±4)   ──┼─▶ refute against real lines    │
 │  trimmed intermediate steps ─┘                                │
 └───────────────────────────────────────────────────────────────┘
 example: a "untrusted pointer flows into a TA deref" claim → Challenger sees it's bounds-checked
          one step earlier → refutes → false alarm gone before it reaches a human.
```

### 2.2 · Narrow the Verifier's view (self-consistency)
*effort S–M · ★★ precision + cost · stage ⑤*

A **slice** = the code reachable from the hypothesis's cited line (±a few functions). Instead of reading the whole function, run the Verifier three times on progressively narrower slices and synthesize.

```
 ┌─ ⑤ Verifier (zoom) ─  [CHG] ──────────────────────────────┐
 │  NOW:   read the whole function                            │
 │  ═══════ CHANGES to slice + self-consistency: ═══════      │
 │  AFTER:  whole fn ──▶ 3× narrower slices ──▶ synthesize    │
 │         (drop unreachable branches → fewer tokens)         │
 └────────────────────────────────────────────────────────────┘
 example: a 400-line init function with a reachability claim → 3 narrow passes keep the ~60-line
          reachable branch → verdict on that, not the whole function.
 caveat: the reference method shipped no evaluation — require a measured precision gain before stacking.
```

### 2.3 · Map where the authors already put defensive checks
*effort S–M · ★★ evidence (new Tier-1 facts) · stage ④*

The scanner doesn't know *where checks already are* — which is exactly where a missing check is interesting. (In Rust, `unsafe` is the *opposite* of a guard — it opts out of safety — so it must NOT be mined as one.)

```
 ┌─ ④ INVESTIGATE (zoom) ────────────────────────────────┐
 │  Planner actions {...}                                 │
 │               + mine_guards   ◀═══ (NEW)               │
 │                     │                                  │
 │                     ▼  finds assert / panic! /         │
 │                        return Err / bounds checks      │
 │                        (NOT unsafe)                    │
 │                     │                                  │
 │                     ▼  tool facts  (Tier-1)            │
 └───────────────────────────────────────────────────────┘
 existing internal/staticcheck is only an adapter registry — no guard miner today.
```

### 2.4 · Detect a dependency still carrying a known, unfixed bug
*effort split: S–M method, L matcher · ★★ precision · stage ④/⑤*

If a target is pinned to a buggy SDK version *and* lacks the upstream fix, that's a citable finding.

```
 ┌─ SDK fix commit ────────────────────────────────────┐
 │  buggy version ─┐                                    │
 │  fixed version ─┴─▶ diff ──▶ {buggy pattern,         │  (NEW: diff analyzer)
 │                               fixed pattern}        │
 └──────────────────────────┬───────────────────────────┘
                            ▼
 ┌─ ⑤ matcher (NEW) ─────────────────────────────────────────┐
 │  target matches buggy AND NOT fixed?  ═══▶ finding        │
 └────────────────────────────────────────────────────────────┘
 do NOT port ZepCompare's matcher (Solidity-only). Build small: tree-sitter over diffs + an alias
 resolver (SVF for C/C++, rust-analyzer for Rust). Descope to one SDK (dcap-qvl).
```

---

## Phase 3 — Confirm bugs by running them (the big, expensive bet)

### 3.1 · Verify a finding by fuzzing until it crashes
*effort L · ★★★★ recall ceiling (TEE-fidelity-gated) · stage ④→⑤*

A finding stalls at "likely issue" with no executable proof. A reproduced crash is the strongest grounding.

```
 ┌─ ④ INVESTIGATE (zoom) ───────────────────────────────┐
 │  Planner actions {...}                                │
 │              + dynamic_verify      ◀═══ (NEW)         │
 │                    │                                 │
 │                    ▼  directed fuzz toward an assert │
 │   ToolFact "tee.dynamic.fuzz_crash_repro" ◀═══ (NEW) │  (Tier-1)
 └──────────────────┬───────────────────────────────────┘
                    ▼  new evidence
 ┌─ ⑤ Arbiter (zoom) ─  [CHG] ───────────────────────────────────┐
 │  likely_issue ──[crash ToolFact present]──▶ confirmed_candidate │
 └─────────────────────────────────────────────────────────────────┘
 example: integer overflow in TA_OpenSession param parsing → directed fuzz → ASAN crash in
          QEMU+OP-TEE → crash ToolFact. A host-process surrogate would catch the overflow but MISS a
          sealing-key leak only a real enclave exposes — hence the in-enclave gate.
 substrate: OP-TEE/QEMU(+RPMB emulation) or SGX-sim. Gate ★★★★ on ≥1 in-enclave repro.
```

### 3.2 · Generate the fuzzing harness automatically
*effort M–L · ★★★★ (unblocks 3.1) · stage ④*

Writing each harness + invariant-assert by hand is the hardest part of 3.1. A planner action drives a coding agent to emit a ready-to-run harness.

```
 ┌─ ④ INVESTIGATE (zoom) ────────────────────────────────┐
 │  Planner actions {...}                                 │
 │             + synthesize_harness   ◀═══ (NEW)          │
 │                    │                                  │
 │                    ▼  via JSON-over-stdio  ◀═══ (NEW)    │
 │              [coding agent]                            │
 │                    │                                  │
 │                    ▼  {entry_fn, param_types,          │
 │                       invariant_assert}               │
 │                       → harness + assert + build cmd   │
 └───────────────────────────────────────────────────────┘
 the generated harness is LLM code (agent-tier); only its crash OUTPUT is a tool fact (Tier-1).
 Build the bridge before rating the effort M.
```

### 3.3 · Make the Arbiter trust execution evidence over opinions
*effort M · ★★★★ precision / fixes same-model bias · stage ⑤*

All four agents may be one model agreeing with itself. The fix: execution evidence (a crash) escalates a finding; an agent opinion does not.

```
 ┌─ ⑤ Arbiter (zoom) ─  [CHG] ───────────────────────────────┐
 │  the Arbiter already receives typed context (buildSections) │
 │  ═══════ ADD a weighting rule: ═══════                       │
 │    [tool fact: crash]   ▲  escalate                         │
 │    [agent opinion]      ▼  do NOT escalate                  │
 └─────────────────────────────────────────────────────────────┘
 (The agentbus *Q&A* channel is the "hollow" part — same model answers itself. The Arbiter's
  typed context delivery is a separate path and already works. 3.3 only adds the weighting rule.)
 pairs with 5.4 (different models per agent = the complementary, model-layer bias fix).
```

---

## Phase 4 — Measure the gain (make the benchmark gate the tool)

The benchmark is already rigorous: 44 cases = 88 samples, every case a checked-in vulnerable+fixed pair.

### 4.1 · Pass only if it finds the bug AND stays quiet on the fix
*effort S · (evaluation) · stage ⑥*

A scanner that flags everything passes a recall-only benchmark. Pass a case only if vulnerable→finding AND fixed→no-finding.

```
 ┌─ ⑥ benchmark gate (zoom) ────────────────────────┐
 │  case PASS  iff  (vuln→finding) AND (fixed→∅)     │  ◀═══ (NEW gate)
 │  (corpus already paired: 44 cases = 88 samples)   │
 └───────────────────────────────────────────────────┘
```

### 4.2 · Measure whether each agent earns its place
*effort M · (evaluation) · stage ⑥*

Nobody knows if Challenger/Verifier/Arbiter add correctness vs a lone Expert.

```
 ┌─ ⑥ benchmark (zoom) ─────────────────────────────────────┐
 │  run each config over the 44 cases vs single-Expert:      │
 │   --ablate=challenger | verifier | arbiter | bus          │  ◀═══ (NEW flag)
 │  via the RunWithClient DI seam (run.go:96)                │
 └───────────────────────────────────────────────────────────┘
```

### 4.3 · Check generated specs against human-curated ones
*effort M · (evaluation) · stage ⑥ · depends on 1.1*

Once 1.1 auto-generates playbooks, check them against curated gold. **Agreement** = Jaccard overlap of the two `required_evidence` sets, per family (intersection ÷ union). e.g. generated lists 5, gold lists 6, 4 overlap → 0.67.

```
 ┌─ ⑥ benchmark (zoom) ─────────────────────────────────────┐
 │  generated playbook ──▶ agreement check ──▶ score         │  ◀═══ (NEW audit)
 │  (needs the curated gold set from 1.1 first)              │
 └───────────────────────────────────────────────────────────┘
```

### 4.4 · Add attestation / Web3 targets to the corpus
*effort L (or time-box) · (evaluation) · stage ⑥*

The corpus leans OP-TEE/Arm C and lacks attestation depth. (A Web3 example scan already exists at `examples/oasis-sdk-scan/`.)

```
 ┌─ ⑥ benchmark/datasets (zoom) ───────────────────────┐
 │  + dcap-qvl buggy/fixed pairs   ◀═══ (NEW)           │
 │  exit criterion: ≥6 pairs, or descope                │
 └───────────────────────────────────────────────────────┘
```

---

## Phase 5 — Ship it (reliability, cost, cleanup)

### 5.1 · Stop the scanner getting stuck in loops
*effort S · ★ reliability · stage ④*

**Goal: wire the no-progress (`Stall`) detector safely.** It's deliberately unwired today because naive wiring kills every run on round 3 (it needs agents to emit partial progress first). The work:

```
 ┌─ ④ planner loop (zoom) ───────────────────────────────────────┐
 │  LoopDetector   ✅ already wired (planner.go:162)               │
 │  StallDetector  ┄┄┄ unwired on purpose (kills runs at round 3)  │
 │  ═══════ to wire it safely, first: ═══════                      │
 │    1. ADD overflow-compression + repeated-block dedup           │
 │    2. make agents emit partial progress (the prerequisite)      │
 │    3. then wire StallDetector on that signal                    │
 └─────────────────────────────────────────────────────────────────┘
```

### 5.2 · Cache repeated verdicts to save budget
*effort M · ★ cost · stage ④*

Re-verifying identical situations wastes the LLM budget.

```
 ┌─ ④ TrustIR (zoom) ─────────────────────────────────────┐
 │  AnnotateFactTable result ──▶ memo                     │
 │  key = (TWE family, evidence fingerprint)   ◀═══ (NEW) │
 │  invalidate when the playbook schema bumps             │
 └─────────────────────────────────────────────────────────┘
 (not IRIS's source/sink key — it doesn't fit TEE findings.)
```

### 5.3 · Reconcile the README  (legacy-scanner retirement is ✅ done on main)
*effort S · (polish) · stage ⑥*

The legacy **non-LLM scanner** mode + `internal/{scanner,mapper,hotspots,repomap}` were retired on main (`cfg.Mode` is now hardcoded to `llm`). What remains is **README cleanup**: the README still references a sink catalog `knowledge/sinks/rust.json` that does not exist (intentionally absent), plus dead `--max-hotspots` / `sink_hits.json` / `hotspots/` mentions.

```
 ┌─ README (still stale) ───────────────────────────┐        ┌─ code ──────────────────────────┐
 │  "sink catalog: rust.json"     ┄┄┄┄┄┄ MISMATCH ──┼───────▶│ knowledge/sinks/rust.json  ✗    │
 │  "--max-hotspots" / sink_hits   (dead refs)      │        │ (intentionally absent)           │
 └────────────┬─────────────────────────────────────┘        └──────────────────────────────────┘
              │ delete the dangling refs
              ▼
 ═══════ fix the README: drop the rust.json / sink-catalog / --max-hotspots / hotspots refs. ═══════
 NOTE: do NOT retire cmd/twescan + internal/twepipeline — they are now the benchmark runner's
 deterministic TWE scanner path, not legacy. querygen stays live CodeQL code.
```

### 5.4 · Validate non-GLM model providers
*effort M · (polish; enables 3.3) · stage ⑥*

Only the GLM provider is validated today.

```
 ┌─ ⑥ providers (zoom) ──────────────────────────────────┐
 │  GLM preset (validated)                                │
 │  OpenAI preset  ┄┄┄ untested                           │
 │  ═══════ ADD: smoke-test via RunWithClient DI ═══════  │
 │  (model-layer half of 3.3's bias fix)                  │
 └─────────────────────────────────────────────────────────┘
```

---

## A note on the numbers

Figures like "IRIS roughly doubles recall" and "Vul-RAG halves false positives" come from the **papers**, not the reference repos — treat them as the authors' claims. The locally-checkable facts are real and verified: the benchmark has 44 cases / 88 paired samples; the GLM smoke run is archived (F1 0.5, paired pass 1/3, `teecheck-benchmark/reports/2026-07-12-glm-smoke.md`); the two schema copies are kept in sync automatically by a test (`internal/schema/schema.go`); the seven TWE families are defined in `knowledge/twe/definitions/taxonomy.yml`.

**Re-validated against `main` (`7c72016`, 2026-07-31):** playbook→CasePack wiring (was 0.1's other half), tiered playbook injection (was 1.2), and legacy-scanner retirement (most of 5.3) are now **done on main** and marked ✅. Playbook coverage is State + Flow (2 of 7); the remaining file/line references were refreshed.

**Playbook value is unmeasured (item 1.1 downgraded from ★★★★★ to ★★★).** The only with/without-playbook A/B was voided — it ran while the delivery pipe was disconnected (`bf9ead6`) and the CasePack merge silently dropped playbook fields (`22350e0`, now fixed) — so `guard.yml` was withdrawn on a null result that doesn't hold. The team's real finding (`08e22cd`): playbooks divide by **obligation-shape, not TWE family** (Flow's obligations already covered all Guard cases). So 1.1 now leads with *re-run the A/B on the fixed pipe*, then populate by shape — not author one playbook per family. Note: playbooks are **not** redundant with profile+invariants+TWE (they uniquely carry `common_false_positives` and the family-generic defense vocabulary), and `tee-usage-scanner/docs/ARCHITECTURE.md §2.2` records the team's deliberate choice to inject all playbooks rather than retrieve by profile.
