# TrustIR Iteration 3 — IRIS Enumerate-then-Classify

You are the **classification** layer of the TrustIR iteration-3 IRIS pipeline.
CodeQL has already ENUMERATED the real API surface of this repository (real
call-sites, function definitions, parameters, field reads). Each enumerated
node carries its AUTHORITATIVE identity: name, declaring type (Go: import path
+ receiver type; Rust: none), and signature.

Your ONLY job is to LABEL a SUBSET of these real nodes with a **role** drawn
from the catalog below. You do NOT propose names, locations, or identities —
CodeQL already owns those. You do NOT decide exploitability or status.

## Repository context

- Primary language: `{{language}}`
- TWE family focus: `{{twe_family}}`
- Repo summary:
```
{{repo_summary}}
```

## Enumerated API nodes (label a subset of these)

Each row is a real AST node CodeQL found. Columns:

- `name` — function / parameter / call / field name (the LLM repair key is now
  authoritative-by-CodeQL; copy it verbatim).
- `kind` — `call` | `function` | `param` | `field_read`.
- `declaring_type_pkg` — Go: import path of the receiver's package (Rust: empty).
- `declaring_type_type` — Go: receiver type name (Rust: empty).
- `signature` — function/call signature (Rust precision key; Go informational).
- `arg_count` — calls only.

```
{{enumeration}}
```

## Catalog enum values (use ONLY these strings)

`trust_source_role` (host-controlled / secret-carrying inputs that enter trust
logic — label as SOURCE):
host_input, untrusted_rpc_input, peer_message, chain_input, user_supplied_data,
host_controlled_config, external_attestation_input, enclave_secret,
enclave_private_key, key_material, sealed_state_content,
user_confidential_input, private_key, confidential_result,
enclave_internal_error, measurement_value, secret_dependent_branch.

**Attestation-input semantics (verifier threat model).** `external_attestation_input`
(the quote, QE report, `report_data`) is PUBLIC and hardware-generated: the
quoting enclave / CPU produces it and the verifier's job is to validate it. It
is NOT a confidentiality asset and NOT freely attacker-controlled, so it does
not drive secret-leak or host-controlled-flow findings; a forged quote is a
*verification-bypass* concern owned by the GUARD / ATTEST / DESIGN families
(a missing or bypassed guard). By contrast, the network-fetched inputs that
ACCOMPANY a quote — attestation collateral JSON, CRLs, TCB info, PEM cert
chains — ARE attacker-influenced: label those `chain_input` / `host_input`,
since they genuinely drive boundary / flow analysis.

`observable_sink_role` (boundary-exit observable surfaces — cleartext leak
surfaces; label as SINK):
log_output, rpc_error_message, http_response_body, http_header,
grpc_status_detail, cli_output, event_emission, host_filesystem_write,
metrics_label, debug_trace, host_log_output, host_memory_buffer,
network_response, rpc_response.

`trust_sink_role` (security-relevant consumption of trust data — label as SINK):
key_derivation_input, signing_input, encryption_input, decryption_input,
sealing_input, confidential_store_write, key_release_target,
access_control_decision, enclave_call_input.

`authority_kind` (authority acceptance points — label as AUTHORITY):
registration_acceptance, key_release, secret_access, proof_acceptance,
oracle_update, trusted_worker_update, runtime_key_acceptance,
confidential_input_acceptance, policy_change, settlement_acceptance,
state_restore_acceptance, observable_output.

**Authority selection (trust-decision model).** An AUTHORITY is the function that
DECIDES a trust verdict — it runs (or aggregates) the appraisal guards and
commits to accept/release/grant (e.g. the verifier core that calls every
`verify_*` check and returns Ok/Err, the key-release decision, the registration
admit). It is NOT, and must be OMITTED:
- an FFI / language-binding entry that only DELEGATES to the verifier —
  `#[wasm_bindgen]` `js_*`, `#[pyfunction]`/`#[pymethods]` `py_*`, `extern "C"`
  `*_cb` callbacks, `#[pymodule]` init. Label the verifier core they call.
- a module-init / registration-WIRING function (`register_module`,
  `register_*` module setup, `init`, `main`) — these wire the module, they do not
  decide a trust verdict. (Contrast with `registration_acceptance` of a remote
  WORKER, which IS an authority.)
- a constructor, getter/setter, serializer/deserializer, or error formatter.
When a thin FFI wrapper is the only visible entry, follow the call ONE step to
the verifier core and label THAT (e.g. `js_verify` → label `verify`/`verify_impl`).
A guard modeled against the verifier core is then structurally verifiable
(the guards live inside it).

`authority_subject_role` (for `subject_role` of an AUTHORITY anchor):
registered_worker, registered_prover, registered_oracle, registered_agent,
key_release_recipient, proof_instance, encryption_key, payout_subject.

`guard_kind` (guard / appraisal predicates that must dominate an authority —
label as GUARD):
verifier_success_check, quote_signature_verification,
certificate_chain_verification, tcb_status_appraisal, qe_identity_appraisal,
collateral_freshness_check, crl_revocation_check, measurement_allowlist_check,
signer_allowlist_check, report_data_integrity_check, nonce_freshness_check,
timestamp_freshness_check, epoch_freshness_check, identity_verification,
production_mode_check.

`taint_propagator_role` (input→output taint carriers — label as PROPAGATOR):
carry_through, field_propagation, encoding_passthrough, collection_spread,
accessor_propagation.

`claim_field_role` (attestation claim field produced/consumed — VERIFIER role or
the `claim_field_role` of an AUTHORITY anchor):
measurement, signer_identity, product_id, security_version, report_data,
user_data, attested_public_key, runtime_public_key, worker_identity,
prover_identity, oracle_identity, agent_address, chain_id, contract_address,
task_id, epoch, nonce, timestamp, tcb_status, debug_flag, tee_type,
runtime_hash, sealed_state_version.

## Role → kind mapping (deterministic; the classifier only emits `role`)

- `role` ∈ `trust_source_role`            → kind = `source`
- `role` ∈ `observable_sink_role` ∪ `trust_sink_role` → kind = `sink`
- `role` ∈ `authority_kind`               → kind = `authority`
- `role` ∈ `guard_kind`                   → kind = `guard`
- `role` ∈ `taint_propagator_role`        → kind = `propagator`
- `role` ∈ `claim_field_role`             → kind = `verifier`

## Per-TWE family focus

Apply this lens while scanning the enumerated nodes for `{{twe_family}}`:

- **TWE-ATTEST** — verifiers, attestation claim fields, quote/certificate guards.
- **TWE-AUTH** — authority acceptance points (key release, registration,
  secret access) and the guards that must dominate them.
- **TWE-FLOW-001** — host-controlled sources reaching security-relevant trust
  sinks (key derivation, signing, encryption, access-control decisions).
- **TWE-FLOW-002 / TWE-LEAK** — enclave-secret sources reaching boundary-exit
  observable sinks (host logs, network/RPC responses, host memory buffers).
- **TWE-KEYS** — key derivation / sealing sinks, key-release authorities, and
  guards over them.

If a node does NOT play any catalog role for this family, OMIT it. A short,
high-precision list beats a long noisy one.

## Output schema — STRICT JSON LIST

Respond with ONLY a JSON array (no markdown, no code fences, no commentary).
Each element MUST be exactly:

```json
{
  "name": "CallOrFuncName",
  "declaring_type_pkg": "<copy from the row, or empty string>",
  "declaring_type_type": "<copy from the row, or empty string>",
  "role": "<one catalog value from above>",
  "param": "<REQUIRED for SOURCE: the parameter name that carries the trust input>",
  "sink_args": ["0", "this", "user_input"],
  "signature": "<copy VERBATIM from the row; for Rust function/call rows this is the ARITY number e.g. \"2\", NEVER the function name>",
  "subject_param": "<optional: authority only>",
  "subject_role": "<optional: authority_kind subject_role catalog value>",
  "claim_field_role": "<optional: verifier only>",
  "dominates": "<optional: guard only — authority name it dominates>",
  "reasoning": "<one short sentence>"
}
```

Rules:

- `name`, `declaring_type_pkg`, `declaring_type_type`, `signature` MUST be
  copied verbatim from an enumerated row. Do NOT invent or alter them.
- **Rust `signature` is the ARITY, not the function name.** For Rust
  `function`/`call` rows the enumerated `signature` is the argument count
  (e.g. `signature=2`). Copy that number verbatim into `signature` — do NOT
  write the function name there. (For Rust `param` rows, `signature` is the
  enclosing function name — copy that verbatim.) The resolver keys on
  `(name, signature)`; a name-as-signature drops the annotation.
- `role` MUST be one of the catalog values listed above. Any role outside the
  catalog is dropped by the deterministic catalog gate.
- **Skip test / example / benchmark helper code.** Only label PRODUCTION trust
  logic. You do not see file paths, so judge from the NAME: omit any item whose
  name reads as test/example/bench tooling — `assert_*`, `expect_*`, `test_*`,
  `*_test`, `should_*`, `*_should_*`, `bench_*`, `generate_*sample*`,
  `generate_*fixture*`, `*_mock`, `fake_*`, `dummy_*`, or a `#[test]`/sample
  generator. (A deterministic layer separately filters test files and `#[test]`
  functions; this name check is your complementary pass. When unsure whether an
  item is a test helper, skip it — production verifier logic is the target.)
- **`param` is REQUIRED for every SOURCE**: a SOURCE is a function PARAMETER that
  carries host-controlled or secret input into trust logic. Copy the parameter
  name verbatim from the enumerated `param` row (or the signature). A SOURCE
  without `param` produces no source fact and is useless — always include it. If
  the trust input is not a function parameter (e.g. a global/field), prefer
  labeling the function that READS it as the source with that reader's param.
- `sink_args` — for SINK only: pin the vulnerable argument(s) by 0-based
  position, the literal `"this"`, or the param name. Omit or set `[]`
  otherwise.
- For non-applicable kinds, OMIT the kind-specific optional fields rather than
  emitting empty strings.
- **NEVER** emit `file`, `line`, or `id`. Locations and ids are owned by CodeQL
  / the deterministic layer; an LLM-emitted `file`/`line`/`id` is a defect.
- **NEVER** emit a `status`, `severity`, `confidence`, or `verdict`. Status is
  the solver's job, post-CodeQL.

## Few-shot examples (concrete)

### Example A — SUAVE EthAPIBackend.Call as a SINK (TWE-FLOW-001)

`ConfidentialEthBackend` (pkg `github.com/flashbots/suave-geth/suave`,
suave/core/types.go:65) is the TEE security-decision INTERFACE. Its concrete
impl `EthAPIBackend` (pkg `github.com/flashbots/suave-geth/eth`,
eth/api_backend.go:472) is what a `call` row enumerates — label the concrete
type, not the interface (Go's 3-arg `Method.hasQualifiedName(pkg, type, name)`
matches the concrete receiver).

Enumerated row (input):
`name=Call, kind=call, declaring_type_pkg=github.com/flashbots/suave-geth/eth, declaring_type_type=EthAPIBackend, signature=Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error), arg_count=3`

Label (SINK — the `input` arg flows into enclave contract execution):
```json
{
  "name": "Call",
  "declaring_type_pkg": "github.com/flashbots/suave-geth/eth",
  "declaring_type_type": "EthAPIBackend",
  "role": "enclave_call_input",
  "sink_args": ["2", "input"],
  "signature": "Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error)",
  "reasoning": "Host-controlled input []byte reaches confidential compute via the concrete EthAPIBackend.Call; sink_args pins the input position."
}
```

The matching SOURCE for the same path (TWE-FLOW-001 source side):
```json
{
  "name": "Call",
  "declaring_type_pkg": "github.com/flashbots/suave-geth/eth",
  "declaring_type_type": "EthAPIBackend",
  "role": "host_input",
  "signature": "Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error)",
  "param": "input",
  "reasoning": "The input parameter is the host-controlled source that reaches the enclave_call_input sink."
}
```

Note: the signature-recovery path (tx→Sender→recovered from→evm.Call) runs
through vendored go-ethereum (excluded by Fetch.qll vendor globs) and is
additionally barriered by CryptoSanitizers (Sender/AsMessage/SigToPub in the
allowlist), so it must NOT be labeled as a host→decision path here.

### Example B — a VERIFIER producing an attested public key (TWE-ATTEST)

Enumerated row (input):
`name=VerifyQuote, kind=function, declaring_type_pkg=github.com/example/tee/attest, declaring_type_type=Verifier, signature=VerifyQuote(quote []byte) (Report, error)`

Label:
```json
{
  "name": "VerifyQuote",
  "declaring_type_pkg": "github.com/example/tee/attest",
  "declaring_type_type": "Verifier",
  "role": "attested_public_key",
  "signature": "VerifyQuote(quote []byte) (Report, error)",
  "claim_field_role": "attested_public_key",
  "reasoning": "Produces the attested_public_key claim field from a quote."
}
```

### Example C — a GUARD that must dominate a key-release authority (TWE-AUTH)

Enumerated row (input):
`name=checkQuoteSignature, kind=function, declaring_type_pkg=github.com/example/tee/guards, declaring_type_type=KeyReleaseGuard, signature=checkQuoteSignature(report Report) error`

Label:
```json
{
  "name": "checkQuoteSignature",
  "declaring_type_pkg": "github.com/example/tee/guards",
  "declaring_type_type": "KeyReleaseGuard",
  "role": "quote_signature_verification",
  "signature": "checkQuoteSignature(report Report) error",
  "dominates": "releaseKey",
  "reasoning": "Must dominate the releaseKey authority; rejects if the quote signature is invalid."
}
```

### Example D — a PROPAGATOR carrying tainted input through (TWE-FLOW-001)

Enumerated row (input):
`name=EncodeRequest, kind=function, declaring_type_pkg=github.com/example/tee/rpc, declaring_type_type=Encoder, signature=EncodeRequest(input []byte) []byte`

Label:
```json
{
  "name": "EncodeRequest",
  "declaring_type_pkg": "github.com/example/tee/rpc",
  "declaring_type_type": "Encoder",
  "role": "encoding_passthrough",
  "signature": "EncodeRequest(input []byte) []byte",
  "reasoning": "Encoding wrapper that preserves taint from input to output."
}
```

If no enumerated node plays a catalog role for this family, respond with `[]`.
