# Adversarial Independence — Known Gap (Deferred)

**Status**: documented, **not yet implemented**. Captured from architect-review on 2026-04-23.
**Severity**: structural — undermines the "adversarial multi-agent" claim of the harness.

## Problem

The pipeline advertises an adversarial chain:

```
expert → challenger → verifier → arbiter
```

In practice all four stages are:

- the same model family (GLM-4.7)
- the same API key and endpoint
- the same temperature (0.2)
- called sequentially in the same process

and each stage reads the previous stage's output as part of its prompt:

- `challenger.Run` / `buildChallengeLLM` (`internal/challenger/run.go`) reads `hypothesis.json`; the system prompt explicitly says *"Challenge the expert's conclusion"*
- `arbiter.Run` / `arbitrateLLM` (`internal/arbiter/run.go`) reads hypothesis + challenge + verifier memo, then arbitrates
- `verifier.RunWithBus` / `buildMemoLLM` (`internal/verifier/run.go`) reads hypothesis + challenge before judging

This is not adversarial review. It is sequential self-refinement by one model that has already been primed with its own prior output. A model presented with its own assertions in the prompt will not reliably contradict them — this is a property of autoregressive LMs, not a GLM-specific quirk.

Current metrics cannot detect this:
- `NonRubberStampRate` detects *stylistic* pushback, not *semantic* independence.
- `VerifierAgreementRate` is structurally biased and weak as a quality signal: the arbiter reads the verifier's memo before deciding, the LLM agreeing-with-itself bias compounds, and the matching logic in stats is loose enough that near-restatements register as agreement.
- `corroboration_rate` measures self-agreement, not finding quality.

## Why session isolation alone does not fix this

A natural first instinct: *"just give each agent its own session / process / API key"*.

This does not help. Each `client.Generate` call is already independent — there is no cross-call LLM memory. The correlation comes from **prompt content**, not from conversation state. If the challenger's prompt still contains the expert's `SuspectedIssue / SupportingFacts / MissingObligations`, the challenger is primed regardless of how isolated the HTTP request is.

The fix has to change **what information each agent sees**, not **how the call is dispatched**.

## Related gap — agentbus is hollow

`NewLLMHandler` (`internal/agentbus/handlers.go`): when verifier calls `bus.AskForCase` targeting `expert-001`, the handler uses a stateless one-line system prompt (`"You are the Expert Agent in TEECheck."`) with **no case context, no snippets, no original hypothesis**. The bus-expert answers only from the verifier's question text. The response is then injected back into the verifier as if it were the expert's view.

This creates the appearance of inter-agent dialogue but provides zero epistemic value — the bus-expert is a zero-context oracle that will confirm whatever the verifier asked, dressed up as the expert's opinion.

## Remediation tiers

Ordered by cost. Lower tiers are compatible with v1's GLM-only scope.

### Tier 1 — Input blinding (single model, cheap)

Strip upstream framing from downstream agents:

- Challenger receives only the case pack + source snippets. **No hypothesis.**
- Challenger produces an independent judgment: *"is there a bug here?"*
- A lightweight compare step diffs expert vs challenger conclusions:
  - agree → high signal
  - disagree → genuine `needs_review`

Trade-off: challenger's role changes from "refuter" to "parallel auditor". The adversarial semantics are weaker but at least real.

**Estimated effort**: ~20 LOC change in `challenger/run.go` + a compare step. A/B-able against the current flow.

### Tier 2 — Sequential reveal with delayed priming

- Verifier first sees only the snippets and is asked to judge independently.
- Then it is shown the expert's hypothesis and asked *"does this change your mind?"*
- Frequent flip-flopping is itself a quality signal for the finding.

Arbiter gets the same two-phase treatment. Requires adding a `pre_reveal_status` field to `VerificationMemo`.

### Tier 3 — Model heterogeneity (v2 material)

- expert = GLM
- challenger = Claude
- verifier = GPT

This is the only structural fix for same-model bias. Deferred to v2 alongside multi-provider support. Blocked by:
- v1 scope decision (GLM-only, see `memory/project_v1_scope_glm_only.md`)
- current `NewAnthropicClient` is really a GLM client against an Anthropic-compatible endpoint (`MaxTokens: 16384` hard-coded, `anthropic-version` header) — adding real Claude requires reworking the provider abstraction, not just config

### agentbus fix (orthogonal, needed regardless)

Two options:

- **delete** `agentbus` from the verifier/arbiter path; the perceived value is cosmetic
- **or** require the handler to load the target agent's actual artifact for that case (hypothesis JSON, challenge JSON, memo JSON) before answering, so responses are grounded in what the agent actually produced

The middle state (hollow handler) is the worst option — it creates false confidence.

## Suggested implementation order (when picked up)

1. Tier 1 challenger blinding — small, measurable, v1-compatible
2. Agentbus fix (delete or ground) — structural hygiene
3. Tier 2 verifier two-phase — flag-gated, A/B against Tier 1
4. Tier 3 model heterogeneity — v2 milestone, requires provider refactor

## Appendix — full architect-review findings (2026-04-23)

Kept here for context; each has its own code pointers.

### Top 5

1. **Single-model adversarial is vacuous** — this document.
2. **agentbus Q&A loops back to the same model with a weaker prompt** — `NewLLMHandler` in `agentbus/handlers.go`.
3. **Verifier snippets are not checked against disk** — expert `SupportingFacts` are grep output captured as prose, never byte-compared; `citation_rate` in `stats.collectExpert` counts any `file.rs:42` substring as a citation regardless of whether that line still says what the expert claimed.
4. **Partial-failure atomicity** — stages write `%03d.json` by index with no checkpoint/resume. A crash between cases 4 and 5 causes silent overwrite on retry; a missing earlier-stage file aborts all downstream stages with a bare `open: no such file` (verifier and arbiter `Run`).
5. **Metrics measure self-agreement, not quality** — `corroboration_rate`, `pipeline_yield`, `cost_per_corroborated`, `VerifierAgreementRate` all share one model's opinions as both numerator and denominator. No ground-truth anchor.

### Secondary

- **Dedupe is formatting-based, not semantic** — `isDuplicate` in `pipeline/dedupe.go`. `auth.rs::verify` and `auth.rs::init` count as different targets; a whole-file candidate (no symbols) is dropped by the `len==0` short-circuit.
- **Snippet truncation has no downstream signal** — `formatSnippets` in `verifier/run.go`. 20k chars/snippet + 60k total cap; omitted snippets produce a text note but the memo has no `truncated` flag, so arbiter cannot tell partial-evidence memos from full-evidence memos.
- **Bus construction duplicated in three places** — `buildStandaloneBus` and `buildCuratorBus` in `cmd/teecheck/main.go`, `buildPipelineBus` in `pipeline/run.go`. Silent divergence risk.
- ~~**`collab-run` / `mapper` / `repomap` are dead code in L3 mode**~~ — `collab-run` was removed on 2026-07-31 (the April orchestrator, superseded by `pipeline.Run`; the non-LLM branch that made it reachable went with heuristic mode). `mapper` is NOT dead — `pipeline/run.go:268` calls it. `repomap` is still unreferenced by the pipeline and remains a candidate.
- **Provider abstraction is thinner than it looks** — `NewClient` / `NewAnthropicClient` in `internal/llm`. The Anthropic client actually targets GLM's Anthropic-compatible endpoint with `MaxTokens` hard-coded and the `anthropic-version` header pinned. Adding real Claude/GPT requires reworking this, not just flipping a config value.
- **Obligations wiki has no size governance** — `LoadObligations` in `planner/obligations.go` concatenates all `.md` files verbatim into every planner round. 3 files today is fine; 50 entries × 300 bytes would add ~3.75k tokens per call with no cap, no pagination, no relevance filtering.
- **Heuristic verifier corroborates by keyword** — `buildMemo` in `verifier/run.go` (non-LLM mode). Marks findings `corroborated` when any grep hit contains `todo`/`fixme`/`missing`. This is the default path unless `--mode llm` is set explicitly.

## Scope of this document

This is a **structural risk record**, not the precision-loop roadmap.
Precision work (events instrumentation, executor sandboxing,
byte-citation contract A1, ground-truth labels D1, review REPL) lands
inside the v1 line because it directly attacks the 6/6 false-positive
rate observed on oasis-core. The independence problems described
here are downstream of that work: it is cheaper to first measure
quality (D1) and force evidence (A1) than to argue about challenger
priming. Tier 1 input blinding becomes a real experiment once the
labels exist; Tier 3 model heterogeneity is v2 material once the
provider abstraction is generalized beyond GLM.

## See also

- `docs/ARCHITECTURE_RESERVATIONS.md` — broader scope of intentionally deferred decisions
- `docs/MULTI_AGENT_HARNESS.md` — current architecture as shipped (with cross-links into this document)
- `docs/EVENT_SCHEMA.md` — typed event stream + the forthcoming `claim_emitted` citation contract that will mechanize A1
