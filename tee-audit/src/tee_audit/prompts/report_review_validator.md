# Report Correctness Review Prompt

You are reviewing a TEE usage audit report for rendering and correctness issues.

## Report Summary
- Active findings: {{finding_count}}
- Unknowns: {{unknown_count}}

## Report Markdown

{{report_markdown}}

## Checks

Review the report and fix these issues:

1. **Table rendering**: All markdown tables must have proper pipe alignment, a header row, and a separator row (`| --- |`). Missing columns break rendering.

2. **Mermaid diagrams**: All `mermaid` code blocks must have valid syntax. Node labels must be 50 characters or fewer. No split nodes.

3. **Trust boundary traces**: Every TEE-relevant finding (Low+ severity in the main body) should have a "Trust Boundary Trace" table with 4 columns: Source Zone, Crossing Point, Sink Zone, Verification.

4. **Markdown formatting**: No orphaned code blocks, no unclosed formatting, no broken headers.

5. **Consistency**: Finding IDs referenced in text should exist. Severity labels should match the finding.

Return the FULL corrected markdown report. If nothing needs fixing, return the original unchanged.
