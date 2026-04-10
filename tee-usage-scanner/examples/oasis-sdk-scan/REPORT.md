# TEECheck Scan Report: oasis-sdk

**Repository:** https://github.com/oasisprotocol/oasis-sdk
**Commit:** `b559f59cab8a964f4a10bf76f7462e3883c6c4d4`
**Scan Date:** 2026-04-06
**Mode:** LLM (all agents)
**Focus:** TEE

## Summary

| Metric | Value |
|--------|-------|
| Code graph nodes | 5,065 |
| Code graph edges | 23,104 |
| Hotspots identified | 6 |
| Cases analyzed | 4 |
| Findings | 4 |

## Findings Overview

| # | Case ID | File | Status | Severity | Confidence |
|---|---------|------|--------|----------|------------|
| 1 | boundary:001 | `tests/runtimes/components-rofl/src/main.rs` | needs_review | low | medium |
| 2 | boundary:002 | `runtime-sdk-macros/src/error_derive.rs` | **no_issue_observed** | low | medium |
| 3 | boundary:003 | `runtime-sdk-macros/src/generators.rs` | needs_review | medium | medium |
| 4 | boundary:004 | `runtime-sdk-macros/src/module_derive/module.rs` | needs_review | medium | medium |

## Key Observations

### Case 002: No Issue Observed
The Auditor correctly identified that `error_derive.rs` is a **compile-time
procedural macro** for error code generation, not a runtime trust boundary.
The original boundary hotspot classification was a false positive from the
automated categorization. The LLM agent properly dismissed it.

### Cases 003 & 004: Macro Code Generation Review
Both cases target proc-macro files in `runtime-sdk-macros/`. The Auditor
noted that while boundary obligations are not visible in the macro utility
code, this does not prove they are missing from the **generated** code.
Recommended follow-up: trace macro expansions at call sites to verify
that generated wrappers enforce caller binding, authorization, and
trust-boundary revalidation.

### Case 001: Test Runtime Boundary
The test ROFL app in `tests/runtimes/` only shows metadata-level `App` trait
implementation. The Auditor correctly flagged this as low-severity but
recommended verifying that `AppId` is not trusted as self-authenticating
identity in production framework code.

## Agent Interaction Quality

In LLM mode, the agents demonstrated:

- **Scanner**: Generated detailed hypotheses citing specific code patterns
  and TEE obligation families
- **Reviewer**: Effectively challenged assumptions, noting that absence of
  visible checks in snippets does not prove absence of checks overall
- **Auditor**: Produced executive summaries with clear risk rationale,
  confirmed facts vs. contradictions, and specific manual follow-up steps

## Artifact Directory

```
examples/oasis-sdk-scan/
├── 00_manifest.json                    # Run metadata
├── 01_profile/project_profile.json     # Detected: Rust, 33 top-level dirs
├── 02_graph/                           # 5,065 nodes (excluded for size)
├── 02_hotspots/hotspot_index.json      # 6 ranked hotspots
├── 03_cases/case-{001..004}.json       # 4 bounded review cases
├── 04_expert/hypothesis-{001..004}.json # LLM-generated security hypotheses
├── 05_challenger/challenge-{001..004}.json # LLM-generated challenges
├── 06_verifier/verify-{001..004}.json  # LLM verification memos
└── 07_arbiter/
    ├── findings.json                   # Final judgment (4 findings)
    └── packets/review-{001..004}.md    # Detailed review packets
```

## How to Reproduce

```bash
cd tee-usage-scanner
go build -o teecheck ./cmd/teecheck/

# Clone oasis-sdk
git clone --depth 50 https://github.com/oasisprotocol/oasis-sdk /tmp/oasis-sdk

# Run the same scan
./teecheck run /tmp/oasis-sdk --focus tee --max-cases 4 --max-hotspots 6 --mode llm \
  --llm-base-url <your-api-url> \
  --llm-api-key <your-key> \
  --llm-model <your-model>
```

## Read the Review Packets

The most informative outputs are the review packets in `07_arbiter/packets/`.
Each one contains:

- Executive Summary
- Confirmed Facts
- Security Interpretation
- Challenger vs. Expert Synthesis
- Risk Assessment
- Recommended Manual Follow-Up
