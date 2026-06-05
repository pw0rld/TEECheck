# Invariant template

For each invariant, fill in:

## Invariant name

## Trust path tag
- critical
- adjacent
- peripheral

## Plain-language statement
What must always be true?

## Analysis family
- Flow analysis
- Guard analysis
- Binding analysis
- State/lifecycle analysis
- Config/build/deployment analysis

## Why it matters
What security property depends on it?

## Sources
What inputs / values / events begin the interesting flow?

## Sinks
What trusted action, dangerous operation, or externally visible event matters?

## Required guards
What checks or policy gates must appear before the sink?

## Likely failure modes
How could this fail in practice?

## Likely code locations
What files / modules / functions are likely involved?

## Primary tool
- CodeQL
- rg / Semgrep-style structural checks
- Slither
- Joern
- agent-assisted review
- dynamic / fuzzing

## Proof required
What exact evidence is needed before this becomes a finding?

## Likely false-positive conditions
What common patterns would make a suspicious hit non-actionable?
