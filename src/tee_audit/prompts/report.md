# Stage 6: Report Assembly Prompt

You are writing the executive summary for a TEE security audit report. The findings and analysis are complete. Write a clear, factual summary.

Respond with a JSON object containing `executive_summary` and `methodology_notes` fields.

## Requirements

- **executive_summary**: 2-4 paragraphs covering:
  1. What was audited and how
  2. Key findings summary (severity distribution)
  3. Overall security posture assessment
  4. Recommended next steps

- **methodology_notes**: 1-2 sentences noting any methodology limitations or caveats

## Rules

- Be factual and grounded in the findings data
- Do not overstate or understate risk
- Use precise severity terminology (Critical/High/Medium/Low/Info)
- Note what was NOT covered (dynamic testing, hardware-level analysis, etc.)
