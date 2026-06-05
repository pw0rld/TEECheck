# CodeQL Query Generation Prompt

You are generating CodeQL queries for TEE (Trusted Execution Environment) security analysis.

## Target Language

Language: {{language}}

## Language Import Rules — CRITICAL

ONLY import modules for the target language ({{language}}). NEVER mix language modules.

For Rust: `import rust`, `import codeql.rust.dataflow.DataFlow`, `import codeql.rust.dataflow.TaintTracking`
For Go: `import go`, `import codeql.go.dataflow.DataFlow`, `import codeql.go.dataflow.TaintTracking`
For C++: `import cpp`, `import codeql.cpp.dataflow.DataFlow`, `import codeql.cpp.dataflow.TaintTracking`

Do NOT import `semmle.code.cpp.*` in Rust queries. Do NOT import `semmle.python.*` in any non-Python query.

## CodeQL API Reference

### Modern Taint Tracking Pattern (CodeQL 2.20+)

Use `module Config implements DataFlow::ConfigSig` — NOT `TaintTracking::ConfigSig` or `TaintTracking::Configuration`.

```codeql
// {{language}}
{{taint_tracking_template}}
```

**Key rules:**
- Use `module Config implements DataFlow::ConfigSig` with `isSource`, `isSink`, `isBarrier` (NOT `isSanitizer`)
- Use `module Flow = TaintTracking::Global<Config>` to create the flow module
- Use `import Flow::PathGraph` to enable path visualization
- Select with `Flow::flowPath(source, sink)` in the `where` clause
- For Rust: prefer `call.getStaticTarget().(Function).getCanonicalPath().matches(...)` for precision
- Include `isAdditionalFlowStep` for hash/crypto operations when tracking binding chains

### Negative-Flow / Absence Pattern

For Binding and Guard invariants, the vulnerability is the **absence** of a required flow or check. Use this pattern:

```codeql
// {{language}}
{{absence_template}}
```

**Key rules for absence queries:**
- The `not exists(...)` must be SCOPED to the specific acceptance/verification call, NOT global
- The freshness check must dominate the SAME verification call, not just exist anywhere
- Report specific missing checks (e.g., 'no MRENCLAVE comparison found at this acceptance site')
- Do NOT import control-flow guard libraries from other languages

**When to use:**
- Binding: "key MUST be bound to report_data" → find report creation where NO key material reaches report_data
- Guard: "verification MUST check MRENCLAVE" → find acceptance sites where NO MRENCLAVE comparison exists
- NOT for Flow invariants where untrusted data crossing a boundary IS the bug

## Vulnerability Modeling — Most Critical Section

### DO NOT model these as vulnerabilities:
- `verify_quote()` flowing to `register_worker()` — that is normal operation
- Key material flowing into `create_report()` — that IS correct binding
- Any "function A calls function B" without showing what check is MISSING

### DO model these as vulnerabilities:
- **Flow (positive taint)**: Untrusted/host data reaches a trusted enclave decision without validation. Source: host input, OCALL return, untrusted storage. Sink: key derivation, attestation report, enclave decision.
- **Guard (absence)**: Registration accepts a worker but NO comparison of MRENCLAVE, MRSIGNER, ISVSVN, report_data, attributes, or debug flag against expected values is found. Report the SPECIFIC missing check.
- **Binding (negative flow)**: Report/quote is created but NO identity key material flows into the report_data argument. The missing flow IS the bug.
- **State (positive taint)**: Unsealed state from host reaches enclave initialization without epoch/nonce validation.
- **Config (structural)**: Debug mode flag enables weakened TEE configuration in production path.
- **Leakage (positive taint)**: Secret-dependent processing output reaches response length or error message.

### Specific guidance for Binding invariants (e.g., inv-02):
1. Find `create_report` / report generation calls
2. Identify the `report_data` argument
3. Define expected flow: identity key → hash → digest → report_data
4. Report when NO such flow exists: `not exists(key → report_data flow)`
5. Use `isAdditionalFlowStep` for hash/update/finalize/copy operations in the chain

### Specific guidance for Guard invariants (e.g., inv-01):
1. Find worker registration / acceptance sinks
2. Find quote verification calls in the acceptance path
3. Check for SPECIFIC field comparisons: MRENCLAVE, MRSIGNER, ISVSVN, TCB status, report_data, attributes, debug flag
4. Report the exact missing check, not "verification is incomplete"
5. Use `@kind problem` with structural `not exists` for each missing field check

## TEE Security Taxonomy

- **Flow**: Untrusted/host data crosses TEE boundary to trusted decision without encryption or binding. Use positive taint tracking.
- **Guard**: Required TEE verification is missing or incomplete. Use absence/structural queries — find sinks missing specific field checks.
- **Binding**: Cryptographic binding between TEE artifacts is partial or absent. Use negative-flow queries — find sites where expected binding flow is MISSING.
- **State**: Sealed state or checkpoints lack continuity or replay resistance. Use positive taint tracking from unsealed host data.
- **Config**: Build flags, debug modes, or deployment configs weaken TEE. Use structural queries.
- **Design**: TEE placed incorrectly in architecture. Primarily structural analysis.
- **Leakage**: Output length, error detail, or metadata reveals enclave state. Use positive taint tracking from secret processing to response output.

## Project-Specific Taint Specifications

Generate one CodeQL query for EACH taint specification below. Use the project-specific API names listed in the project APIs section.

```json
{{taint_specs}}
```

## Project API Patterns

Use these actual API/function names from the project (not generic patterns):

{{project_apis}}

## Generation Rules

1. For **Binding** and **Guard** families: generate a **negative-flow / absence** query using the absence template. The vulnerability is the MISSING flow or check.
2. For **Flow**, **State**, **Leakage** families: generate a **positive taint tracking** query using the taint template. The vulnerability is the UNWANTED flow.
3. For **Config** and **Design** families: generate a **structural** query (`@kind problem`).
4. Use `isBarrier` (NOT `isSanitizer`) for guard/barrier predicates.
5. Prefer canonical path matching (`getStaticTarget().(Function).getCanonicalPath()`) over wildcard name matching.
6. For binding chains, include `isAdditionalFlowStep` for hash/crypto/update operations.
7. Each query must compile against the CodeQL standard library for the target language.
8. Include `@tags security`, `@tags tee` annotations.

## Output Format

For each generated query, provide:
- `filename`: descriptive kebab-case name ending in `.ql`
- `content`: complete CodeQL query source

Generate queries for ALL taint specs listed above.
