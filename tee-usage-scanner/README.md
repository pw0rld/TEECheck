# TEE Usage Scanner

Prototype project for a TEE usage vulnerability scanner.

The current goal is to validate a scanning workflow that combines:

- Joern as the program graph backend
- A rule-driven candidate detector for TEE usage obligations
- Context slicing from the graph
- An LLM as a second-stage reviewer for ambiguous findings

This repository starts with planning and project scaffolding so we can iterate toward an MVP without mixing it into the existing codebases in this workspace.

## Current Status

Planning stage.

The most important design document is:

- `docs/SCANNER_OUTLINE.md`

## Initial Scope

- Language: C/C++
- TEE focus: OP-TEE / GlobalPlatform style APIs
- Scan target: trusted application (TA) code first
- Detection style: missing validation, missing binding, missing state checks, insecure fallback

## Planned Architecture

1. Parse source and build a Joern CPG.
2. Use TEE-specific rules to locate security-relevant operations.
3. Extract compact evidence packages from the graph.
4. Send those evidence packages, not the whole graph, to an LLM.
5. Emit structured findings and reports.

## Repository Layout

```text
tee-usage-scanner/
├── docs/
├── prompts/
├── rules/
├── src/tee_usage_scanner/
└── tests/
```

## Local Usage

For now, the prototype can be invoked without installation by pointing Python at `src`:

```bash
PYTHONPATH=src python3 -m tee_usage_scanner --show-outline
```

## Next Implementation Targets

1. Define the rule schema.
2. Define the evidence package schema.
3. Add a Joern integration layer.
4. Add a first pass of TA-side candidate queries.
5. Add a simple report format.
