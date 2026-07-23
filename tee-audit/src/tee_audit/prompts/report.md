# Stage 6: Report Assembly Prompt

You are writing the executive summary for a TEE usage audit report. The findings and analysis are complete.

Respond with a JSON object containing `executive_summary` and `methodology_notes` fields.

## Output Rules

- **executive_summary**: 2-3 short paragraphs. No filler. No repetition.
  - Para 1: What was audited — TEE usage patterns, platforms, trust boundaries (1-2 sentences).
  - Para 2: Key TEE usage problems by severity with counts and taxonomy categories (2-3 sentences). Lead with the most severe TEE usage problem.
  - Para 3: Recommended next steps (1-2 sentences).
- **methodology_notes**: 1 sentence noting limitations.
- Use bullet lists for findings breakdown, not paragraphs.
- No hedging phrases like "It is important to note" or "In conclusion".
- Do not repeat the project name in every sentence.
- Focus on TEE usage problems: issues involving TEE primitives (attestation, sealing, measurement, ECALL/OCALL, quote generation/verification, freshness) or TEE trust boundaries (enclave/host, trusted/untrusted).
- Mention which taxonomy categories were hit (Trust Boundary Flow, Verification Gap, Binding Weakness, State Continuity, Configuration Integrity, Design Appropriateness, Output & Metadata Leakage).
- Non-TEE generic code findings go in the appendix — mention the count briefly but do not elaborate.

## Rules

- Be factual and grounded in the findings data.
- Do not overstate or understate risk.
- Use precise severity terminology (Critical/High/Medium/Low/Info).
- Note what was NOT covered (dynamic testing, hardware-level analysis, etc.).
- Every sentence must contain new information. No filler.

## Mermaid Diagram Rules

When generating Mermaid diagrams (architecture diagrams, flow diagrams):
- **Node labels must be 50 characters or fewer.** Truncate longer labels with "...".
- Each node must be ONE complete concept — do not split a single concept across multiple nodes.
- Keep diagrams simple: maximum 15 nodes per diagram.
- Use `flowchart TD` or `flowchart LR` syntax only.
- Avoid special characters in node labels (no parentheses, no pipes, no quotes inside labels).
