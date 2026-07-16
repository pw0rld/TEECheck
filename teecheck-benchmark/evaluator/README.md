# Evaluator

> **Authoritative scorer: `runner/`.** The benchmark's TP/FP/FN/TN, precision,
> recall, F1, specificity, and paired pass rate come from `evaluator/runner`,
> which matches findings to oracles deterministically by **file + TWE family**
> (the OWASP Benchmark / NIST Juliet mechanism). Read that package for the
> numbers that count.
>
> **This package (`judge`/`rag`/`llm` + the top-level `evaluator` command) is an
> EXPERIMENTAL semantic cross-check, not a scorer.** It asks an LLM whether a
> finding and a candidate case describe the same weakness and persists that
> judgment. It is **unvalidated**: per the research (SecVulEval reports only
> ~83% agreement with human labels, 99% CI 73-92%), an LLM judge must be
> validated against a human-labelled agreement set — including hard negatives —
> before its output may be treated as a score. Until that validation exists,
> use these judgments only to surface finding/case pairs a human should review,
> never as a pass/fail verdict.

The evaluator is outside the scanner process. TEECheck receives only a source
directory and produces `findings.json`; it never reads this directory.

The experimental judge flow is:

```text
scanner report -> rag retrieval -> LLM judge -> per-pair judgment (NOT a score)
```

`rag` loads benchmark oracle, vulnerable/fixed source, and patch evidence, then
retrieves candidate cases from the scanner report. The `judge`/`llm` layer
submits the retrieved evidence packet to an OpenAI-compatible LLM endpoint and
persists its structured judgment.

The judge needs an **OpenAI-compatible** `/chat/completions` endpoint and a key
for it. The key is read from `-api-key` or, in order, `GLM_API_KEY`,
`ZAI_API_KEY`, `TEECHECK_LLM_API_KEY`; the model from `-model` /
`LLM_MODEL` / `TEECHECK_LLM_MODEL`. Note this is a **different** endpoint family
from the scanner's `.env.local`, which points at an Anthropic-style z.ai URL
that does not serve `/chat/completions` — sourcing `.env.local` supplies the key
and model but you must still pass an OpenAI-compatible `-base-url` (and a key
valid for it).

Evaluate one scanner report with an OpenAI-compatible endpoint:

```sh
GLM_API_KEY="$GLM_API_KEY" go run ./evaluator \
  -report /tmp/scan/07_arbiter/findings.json \
  -cases datasets \
  -out /tmp/scan/judgments.json \
  -base-url https://open.bigmodel.cn/api/paas/v4 \
  -model glm-4.5
```

The command performs report parsing, Top-K retrieval, LLM judging, and writes
one decision per finding/candidate pair. It is an evaluator command, not part
of the scanner binary.

Run the complete source benchmark:

```sh
GLM_API_KEY="$GLM_API_KEY" go run ./evaluator -batch \
  -cases datasets \
  -results results/llm \
  -scanner-command '. ../tee-usage-scanner/.env.local; (cd ../tee-usage-scanner && go run ./cmd/teecheck run {input} --mode llm --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8)' \
  -base-url https://open.bigmodel.cn/api/paas/v4 \
  -model glm-4.5
```

Each pair gets `vulnerable/judgments.json` and `fixed/judgments.json`; the
aggregate is `results/llm/batch-results.json`.
