# Role-specific model configuration

This is the model-routing reference. See [HARNESS.md](HARNESS.md) for the run
lifecycle and [CONTRACTS.md](CONTRACTS.md) for evidence and decision rules.

`teecheck run` and its `plan` alias accept `--role-config path/to/roles.json`.
`TEECHECK_ROLE_CONFIG` provides the same file path through the environment.
The file is read at startup. Unspecified values inherit the global `--llm-*`
settings. The five primary roles are `planner`, `expert`, `challenger`,
`verifier`, and `arbiter`. The optional `scout` role inherits the resolved
planner settings before applying its own overrides; an unknown role or field
is rejected. All resolved routes, including scout, are recorded and checked
when resuming a run.

Example overrides:

```json
{
  "planner": {
    "provider": "openai",
    "base_url": "https://your-provider.example/v1",
    "model": "planner-model",
    "transport": "responses",
    "reasoning_effort": "high",
    "api_key_env": "TEECHECK_PLANNER_API_KEY",
    "timeout_seconds": 300,
    "max_output_tokens": 32768
  },
  "scout": { "model": "scout-model" },
  "expert": { "model": "review-model" },
  "challenger": { "model": "review-model", "temperature": 0 },
  "verifier": { "model": "verification-model" },
  "arbiter": { "model": "review-model" }
}
```

`api_key_env` names an existing environment variable. Inline `api_key` values
are not accepted in this JSON file. Every role can instead inherit the global
credential. Changing `provider` does not implicitly replace other inherited
fields: set `base_url`, `transport`, and `reasoning_effort` together as needed;
an explicit empty reasoning effort clears the inherited value.

Streaming is opt-in: `--llm-stream` or `TEECHECK_LLM_STREAM=true` enables SSE
for OpenAI-compatible Chat Completions (`provider: openai` or `deepseek`,
`transport: chat_completions`). A role can set `"stream": true` or explicitly
set `"stream": false` to override an inherited value. For example:

```json
{
  "planner": { "transport": "chat_completions", "stream": true },
  "verifier": { "stream": false }
}
```

The default remains non-streaming. `responses` and the `glm` preset's
Anthropic transport do not support this option; explicitly enabling it for
those combinations is rejected. A GLM model exposed through an OpenAI-compatible
Chat Completions gateway can use `provider: openai` with that gateway's base URL.
Streaming requests include final usage statistics and preserve content whitespace.
They can keep an idle gateway connection active once the provider sends chunks,
but do not guarantee that the provider emits its first chunk before a gateway's
timeout. The CLI still returns a complete model response to each agent.

Each role's resolved settings appear under `metadata.role_llm` in the run
manifest. Credential values and URL user-info/query parameters are omitted.
LLM events record the configured model for the role that made the call,
including replies requested through the agent bus. Legacy architecture and
invariant stages, when enabled, use the planner role.

Routing is fixed before the run. A policy refusal remains a refusal and does
not trigger a model change or prompt rewrite.

For embedding, `pipeline.RunWithClients` accepts a `RoleClients` structure.
Its `Default` client fills unspecified roles. `RunWithClient` remains a thin
compatibility wrapper that supplies the same client to every role.

Typed case contracts are independently reviewed by Expert and Challenger, then
assessed by Verifier. Their Arbiter uses the validated assessments directly and
does not require a further model call. The Arbiter profile remains available for
legacy case review and agent-bus requests. `verify-contract` uses the Verifier
profile only; absent model/tool prerequisites produce an unresolved recheck.

For DeepSeek, use `"provider": "deepseek"`. The preset uses Chat Completions at
`https://api.deepseek.com/v1` and defaults to the current `deepseek-flash` model.
Explicit model names are retained for compatible gateways. A legacy
`deepseek-chat` role gets an 8,192-token default only when no budget was supplied;
`max_output_tokens` and explicit global budgets take precedence. Switching a
role to a different model recomputes inferred defaults rather than inheriting
the legacy cap. Current thinking models support `reasoning_effort`, including
`none` to disable thinking; `deepseek-reasoner` omits temperature and does not
assume support for the newer thinking-mode controls.
