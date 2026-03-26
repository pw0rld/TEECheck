# Scanner Outline

## 1. Problem Statement

The scanner should detect TEE usage vulnerabilities: cases where the developer uses TEE APIs or trust boundaries incorrectly and weakens the intended root of trust.

The scanner is not primarily a memory corruption detector. It is aimed at obligation failures such as:

- missing validation of REE-controlled inputs
- missing binding between caller, session, object handle, and command
- missing state transition checks
- missing integrity, freshness, or rollback validation
- insecure fallback after TEE failure

## 2. MVP Scope

The first prototype should intentionally be narrow:

- TEE family: OP-TEE / GlobalPlatform style APIs
- language: C/C++
- target: TA-side handlers and security-sensitive helper functions
- analysis depth: intra-procedural first, selective inter-procedural summaries second
- AI role: second-stage reviewer only

## 3. High-Level Pipeline

### Stage A: Frontend and Graph Build

Input:

- source tree
- include paths or build hints if needed
- TEE SDK model

Output:

- Joern CPG with AST, CFG, CDG, DDG, and call graph layers

Purpose:

- create a single graph representation for later queries

### Stage B: TEE Semantic Modeling

We define a TEE domain model outside the code:

- entrypoints
- sensitive operations
- validators
- binders
- state transitions
- fallback operations

This should live in data files so the scanner logic is not hardcoded to one SDK forever.

### Stage C: Candidate Discovery

The scanner should first find security-relevant operations, not findings.

Candidate examples:

- use of `params[i].memref`
- command handlers
- session or object-handle based operations
- key generation, key usage, unseal, decrypt, sign, verify
- shared memory copy or parse operations

### Stage D: Context Extraction

For each candidate, the scanner should extract an evidence package:

- local code snippet around the sensitive point
- backward data slice
- dominance-relevant checks
- small call-chain summary
- discovered bindings and state transitions

The graph stays local. The LLM sees only the extracted evidence.

### Stage E: Rule Evaluation

Rules should be deterministic wherever possible.

Each rule should describe:

- trigger
- required checks
- required bindings
- forbidden patterns
- confidence strategy

### Stage F: LLM Review

The LLM should only answer questions such as:

- does the extracted evidence indicate a missing obligation?
- is an existing check semantically sufficient?
- is the candidate likely a true finding or a false positive?

### Stage G: Reporting

Output:

- JSON findings
- SARIF later
- optional markdown summaries for triage

## 4. Core Components

### 4.1 `frontend`

Responsibilities:

- invoke Joern
- manage import workspace
- cache graph artifacts

### 4.2 `tee_model`

Responsibilities:

- load SDK semantics
- define API categories
- define security object types and relations

### 4.3 `candidate_finder`

Responsibilities:

- run graph queries that locate sensitive operations
- return candidate IDs with source locations

### 4.4 `context_slicer`

Responsibilities:

- collect local code
- collect dataflow facts
- collect control predicates
- collect bindings and state transitions

### 4.5 `rule_engine`

Responsibilities:

- evaluate deterministic checks
- tag missing obligations
- assign static confidence

### 4.6 `llm_reviewer`

Responsibilities:

- review only uncertain or context-heavy cases
- classify finding status
- produce short reasoning

### 4.7 `reporter`

Responsibilities:

- normalize results
- write JSON and later SARIF

## 5. Rule Schema Draft

Each rule should eventually contain:

- `rule_id`
- `title`
- `scope`
- `target_apis`
- `trigger_query`
- `required_checks`
- `required_bindings`
- `forbidden_flows`
- `severity`
- `llm_review_required`

## 6. Evidence Package Draft

The evidence package sent to the LLM should contain:

- candidate metadata
- rule metadata
- sensitive operation
- relevant code snippets
- discovered checks
- missing checks
- discovered bindings
- short control-flow summary
- short data-flow summary

This package should be compact and stable so prompts stay predictable.

## 7. First Rule Candidates

The first MVP should likely implement only a handful of rules:

1. Missing `paramTypes` validation before using `params[i]`
2. Missing size or bounds validation before memref use
3. Missing session or object-handle binding
4. Missing command authorization checks
5. Missing freshness, nonce, or rollback validation
6. Insecure fallback after failed TEE operation

## 8. Implementation Milestones

### Milestone 0: Planning

- finalize scope
- finalize directory structure
- finalize rule and evidence schemas

### Milestone 1: Local Prototype

- import one small TA codebase into Joern
- write 2 to 3 candidate queries
- emit candidate JSON

### Milestone 2: Rule MVP

- implement first deterministic rule set
- emit evidence packages
- evaluate on a few hand-picked examples

### Milestone 3: LLM Review

- add prompt templates
- add finding classification
- compare static-only vs static-plus-LLM

## 9. Immediate Next Steps

1. Finalize the MVP target codebase.
2. Write `tee_model` data files for one TEE SDK.
3. Define the exact evidence JSON format.
4. Implement the first candidate query.
5. Implement one end-to-end rule.
