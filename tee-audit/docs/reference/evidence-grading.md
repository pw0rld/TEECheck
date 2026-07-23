# Evidence grading and false-positive discipline

Use these labels exactly:

## Confirmed issue

Use only when you have:
- a concrete violated property
- a concrete live-path enforcement gap
- concrete code or config evidence
- enough reachability or deployment context to justify exploitability claims

## Likely issue

Use when:
- the code-level gap is strong
- the trust path is important
- but one important semantic or deployment question remains open

## Weak signal

Use when:
- the pattern is suspicious
- but the current evidence could still be explained by wrappers, lower-level guards, or non-production reachability

## Needs agent validation

Use when:
- the lead depends on runtime state, deployment policy, or protocol assumptions that require deeper agent-assisted investigation to settle

## Positive guards

Keep confirmed positive defenses out of the findings list.

Use them separately to explain why a lead did **not** become a finding:
- report-data binding present
- debug-attribute enforcement present
- measurement policy present
- simulation path documented as non-production

## Evidence basis required

Every candidate finding must cite its evidence basis explicitly:

- CodeQL
- structural search
- agent-assisted path trace
- repo documentation or config evidence

Model reasoning may help propose leads, but it is never enough on its own to justify a finding.

## False-positive discipline

Before reporting a finding, check:
- is this a live path or a helper-only path?
- is the guard implemented in a lower layer that definitely executes?
- is the path test-only, mock-only, or simulation-only?
- is the repo documentation explicit enough to downgrade exploitability?
- is the issue a trust-model mismatch rather than a code bug?
- have you named the concrete invariant this item violates?
