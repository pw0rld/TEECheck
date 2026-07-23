# `tee_audit.trustir` — TrustIR TEE-weakness pipeline

A **deterministic** TEE-usage weakness analysis pipeline, integrated self-contained
into `tee-audit`. It implements the design in
`web3_tee_trustir_docs/TRUSTIR_ENGINEERING_DESIGN_V1.md`:

```
taxonomy family -> TWE entry -> TrustIR instance -> deterministic binder
  -> generated CodeQL facts -> prewritten CodeQL query module -> obligation solver
  -> conservative finding
```

## Iteration 3 — IRIS enumerate-then-classify (current)

Adopted from the IRIS paper ("LLM-Assisted Static Analysis for Detecting
Security Vulnerabilities"). The pipeline inverts v2's "LLM proposes names" into
**CodeQL enumerates real APIs -> LLM classifies roles**:

```
CodeQL fetch queries enumerate real AST nodes (name, declaring-type, signature, loc)
  -> LLM classifies a SUBSET into catalog roles (+ sink_args)            [semantic only]
  -> verify->reject resolver grounds each label against the enumeration  [CodeQL owns loc]
  -> ONE GeneratedTrustFacts.qll (fully-qualified hasQualifiedName)      [kills name collisions]
  -> 16 prewritten TaintTracking queries run once                        [CodeQL verifies]
  -> deterministic solver (8 statuses + State/Design cap)                [solver sets status]
  -> post-hoc triage (write-only llm_vulnerable_hint; solver decides)    [principle preserved]
  -> findings.{json,md,sarif}
```

Key iteration-3 decisions (see `.omc/specs/deep-interview-trustir-iteration3-iris.md`
+ `.omc/plans/ralplan-trustir-iteration3-iris.md`):

- **Repo-wide enumeration, zones dropped.** `codeql/trustir/{go,rust}/fetch/*.ql`
  enumerate call-sites/functions/params/field-reads with authoritative identity,
  excluding vendor/generated/proto (`spec/exclusion.yml`); the exclusion is logged.
- **CodeQL owns location; resolver verify->reject.** The LLM emits
  `{name, declaring_type, role, sink_args, signature, reasoning}` — never
  file/line/id. `resolver/index_resolver.py` grounds each label against the
  `EnumItemIndex` (Go key `(name, declaring_type)`, Rust key `(name, signature)`)
  and inherits location from CodeQL.
- **Fully-qualified matching.** `generator/annotation_facts.py` emits Go
  `target.(Method).hasQualifiedName(pkg, type, name)` (3-arg methods) /
  `(pkg, name)` (2-arg package funcs) + sink arg-position. This kills the suave
  signature-recovery FP (`ConfidentialEthBackend.Call` no longer collides with
  geth's `vmenv.Call`).
- **GUARD + propagators wired.** `hasSuppressor` (GUARD->authority dominance) and
  `isAdditionalTrustFlowStep` (PROPAGATOR) are generated, no longer `none()`.
  Type-barriers (`common/TypeBarriers.qll`, len/cap content-reduction) +
  `CryptoSanitizers` (signature-recovery/verification gates) augment `isBarrier`.
- **Post-hoc triage, solver-decided.** `triage.py` emits a structured signal
  (`self_authenticating`, `guarded_by`, `confidence`) **and** a
  `llm_vulnerable_hint` that is WRITE-ONLY to the finding record. The solver sets
  status from the structured signal + guard evidence only, overriding the hint in
  either direction (because it never reads it).

**Core principle (non-negotiable):** the LLM only performs *semantic extraction*
into a TrustIR candidate (with evidence spans). It must not write CodeQL or emit
vulnerability verdicts. The binder deterministically resolves/rejects; CodeQL
vulnerability logic is prewritten; the solver classifies conservatively.

## Layout (self-contained in tee-audit)
```
src/tee_audit/trustir/
  models.py        Pydantic v2 models + enums (mirror spec/trustir.schema.json + enum_registry.yml)
  loader.py        load/dump TrustIR JSON
  validator.py     schema (pydantic) + cross-field semantic checks
  spec.py          bundled spec files locator
  spec/            taxonomy.yml, enum_registry.yml, twe_catalog.yml, trustir.schema.json
  binder/          deterministic resolver (resolve_file/symbol/field/span; zero-hallucination guard)
  generator/       resolved IR -> GeneratedTrustFacts.qll (FACTS ONLY) + query plan
  extractor/       LLM enumerate-then-classify (CodeQL enumerates; LLM labels; no verdicts/CodeQL)
  taxonomy.py      TWE-id -> family mapping (derive_family)
  solver/          8-status obligation solver (confirmed..unresolved) + State/Design cap
  reporter/        findings.json / findings.md / findings.sarif
  comparison.py    reconcile existing tee-audit report -> family delta
  codeql_runner.py build CodeQL DB (source-only) + run TWE queries + reduce SARIF
  pipeline.py      run_trustir(...) end-to-end orchestration (extract->resolve->CodeQL->solve)
  runner.py        resolve_and_solve(...) deterministic core (bind -> solve)
codeql/trustir/
  go/              Go pack: common libs + 16 TWE queries (codeql/go-all 6.0.0)
  javascript/      JS pack: common libs + 16 TWE queries (codeql/javascript-all 2.6.20)
```

## Usage
```bash
# Full pipeline with LLM extraction (needs GLM/OpenAI key in config):
tee-audit trustir --repo ./my-repo --language go --llm-api glm

# Deterministic run on a pre-built candidate (no LLM, no CodeQL):
tee-audit trustir --repo ./my-repo --annotations annotations.json --no-codeql --twe TWE-BIND-001

# Specific TWEs (repeatable; default = all 16):
tee-audit trustir --repo ./my-repo --twe TWE-BIND-001 --twe TWE-CONFIG-001
```
Outputs `findings.json`, `findings.md`, `findings.sarif`, `comparison.md`
(when an existing tee-audit report exists), and `trustir_summary.json`.

## Toolchain notes
- CodeQL CLI required (v2.24.0+). Go DBs need the Go toolchain on PATH
  (`build_or_get_db` adds `~/opt/go/bin`). JS DBs are source-only. Rust needs a
  real `cargo build` (best-effort; `rust-all` is immature).
- A single qlpack cannot depend on multiple language `*-all` packs (different
  dbschemes), hence one pack per language under `codeql/trustir/`.
