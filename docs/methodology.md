# tee-audit Methodology

## Overview

tee-audit implements a structured, reproducible static audit methodology for analyzing how Web3 and blockchain projects use Trusted Execution Environments (TEEs). The methodology follows seven ordered stages, each producing typed outputs that feed into subsequent stages.

## Principles

1. **Fingerprint before assuming** — Scan the repository for concrete signals before forming hypotheses about its TEE usage.
2. **Ground in architecture** — Understand the design before hunting for bugs. The dossier comes before findings.
3. **Map to invariants** — Every finding must trace back to a named security invariant derived from the trust architecture.
4. **Deterministic first** — Prefer deterministic scanning (CodeQL, structural search) over purely LLM-generated claims.
5. **Conservative findings** — False positives waste reviewer time. Grade confidence honestly. Mark uncertain findings as `NeedsManual`.

## Stage details

### Stage 0: Fingerprint

Pure Python scanning using pathlib + regex. No external dependencies.

Scans the repository for:
- **TEE platforms**: SGX, SEV, TrustZone, AWS Nitro, Confidential Computing, and custom enclave patterns
- **Web3 roles**: validator/consensus, key manager/signer, oracle/bridge/off-chain worker
- **Trust artifacts**: attestation, identity (MRENCLAVE, PCR), sealed state, cryptographic operations
- **Build flags**: simulation mode, debug flags, feature gates
- **Critical paths**: enclave, attestation, key, crypto, trusted directories
- **File extensions**: mapped to CodeQL-supported languages

Output: `Fingerprint` model with all detected signals.

### Stage 1: Dossier

LLM-assisted generation of an architecture dossier. The LLM receives the fingerprint and a structured view of the repository, then produces:

- Component inventory with trust boundaries
- Data flow between TEE and non-TEE components
- External dependencies and their trust assumptions
- Deployment and operational model

Output: `dossier` text and structured `sections` dict.

### Stage 2: Invariants

LLM-assisted extraction of security invariants from the dossier and fingerprint. Each invariant specifies:

- **Trust path**: The boundary being analyzed (e.g., "host → enclave")
- **Analysis family**: Flow, Guard, Binding, State, or Config
- **Sources and sinks**: Concrete entry/exit points
- **Guards**: Expected security checks
- **Failure modes**: What happens when the invariant is violated
- **CodeQL expressibility**: Whether the property can be checked structurally

The invariant set should be small and security-relevant. Every finding in later stages must map to a named invariant.

### Stage 3: Analysis Matrix

Deterministic mapping of each invariant to:

| Column | Content |
|--------|---------|
| invariant_id | INV-NN |
| trust_path | Source → sink description |
| analysis_family | Flow / Guard / Binding / State / Config |
| primary_tool | CodeQL or Manual |
| required_proof | What evidence confirms or denies the invariant |
| likely_fp_conditions | When a positive finding might be a false positive |

Output: TSV and Markdown table.

### Stage 4: CodeQL Scan

Builds a CodeQL database and runs baseline queries. This is the only stage that requires an external tool (CodeQL CLI).

- Database creation with language auto-detection from Stage 0
- Baseline scan with standard security queries
- SARIF 2.1.0 output for downstream triage

If CodeQL is not available, stages 5-6 still run with whatever data is available (triage is skipped, deep verify uses LLM-only analysis).

### Stage 5: Triage + Deep Verify

Two sub-stages:

**5a: Triage** (deterministic) — Grade each SARIF result:
- `ConfirmedIssue`: Clear evidence of a security issue
- `LikelyIssue`: Strong signal but requires one assumption
- `WeakSignal`: SARIF match with incomplete tracing
- `NeedsManualValidation`: Cannot verify without runtime testing

Separates positive guards (confirmed security mechanisms) from potential findings.

**5b: Deep Verify** (LLM) — For each finding cluster, the LLM:
1. Reads the actual code at reported locations
2. Traces the full attack path with file:line references
3. Checks for missed guards the SARIF didn't capture
4. Assigns severity using the impact × exploitability matrix
5. Writes a numbered POC as attack steps

Output: Verified findings with severity, confidence, POC, and remediation.

### Stage 6: Report Assembly

Combines all stage outputs into a final report:

- **Severity dashboard**: Critical/High/Medium/Low/Info × core/adjacent/peripheral matrix
- **Positive guards**: Confirmed security mechanisms
- **Unknowns**: Findings that require manual investigation
- **Executive summary**: 2-4 paragraph LLM-generated summary of the audit

## Severity matrix

|  | Easily Exploitable | Exploitable | Hard to Exploit |
|---|---|---|---|
| **High Impact** | Critical | High | Medium |
| **Medium Impact** | High | Medium | Low |
| **Low Impact** | Medium | Low | Info |

## Confidence grades

| Grade | Definition |
|-------|-----------|
| Confirmed | Code path traced, POC written, guard verified absent |
| Likely | Strong evidence but one step requires assumption |
| Weak | SARIF signal with incomplete code path tracing |
| NeedsManual | Cannot verify without runtime testing or domain expertise |

## Trust-path tiers

| Tier | Definition |
|------|-----------|
| core | Directly on the primary trust path (enclave entry, attestation, key management) |
| adjacent | One hop from core path (configuration, build system, deployment scripts) |
| peripheral | Supporting infrastructure (logging, monitoring, documentation) |

## Limitations

- **Static analysis only** — No dynamic testing, fuzzing, or runtime verification
- **CodeQL coverage** — Limited to languages supported by CodeQL (C/C++, Go, Java, Python, JavaScript, TypeScript, Ruby, Swift, C#)
- **Hardware-level** — Cannot verify hardware TEE behavior (side channels, microarchitectural attacks)
- **LLM accuracy** — Stages 1, 2, 5b, and 6 use LLM reasoning which may produce incorrect claims. All LLM-generated findings should be manually verified.
- **No cross-project comparison** — Each audit is independent. Findings are repo-specific.
