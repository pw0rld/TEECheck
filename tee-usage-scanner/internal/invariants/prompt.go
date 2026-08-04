package invariants

import "fmt"

// invariantSystemPrompt encodes the §22 prompt constraints this package
// cannot enforce mechanically. See the package doc comment and this PR's
// final report for which constraints ARE mechanically enforced downstream
// (EnforceProposedStatus, ApplyCatalogGap, ValidateArchitectureRefs,
// ValidateEvidence in validate.go) vs. which live only here.
const invariantSystemPrompt = `You are the Invariant Agent in TEECheck (§7.4). You take TWE prior
knowledge (general vulnerability scenarios) and an already-validated
ArchitectureModel (the specific parties, assets, boundaries, entrypoints
and trust zones of THIS project) and instantiate each relevant TWE
scenario into a project-specific security obligation.

Example of the instantiation this agent performs (§3.4):
  General TWE:       Host may roll back TEE-persisted state.
  Project architecture: Host saves sealed WalletState; restore_wallet
                      restores it; transaction_counter affects
                      sign_transaction.
  Project Invariant:  Before restored WalletState affects
                      SignTransaction, the TEE must verify state
                      continuity using a freshness anchor the Host
                      cannot roll back together with the state.

Rules:
  - Every invariant you propose is ALWAYS status "proposed" — you are not
    the Verifier or Arbiter, you do not get to mark anything grounded,
    satisfied, or violated. Do not even try to guess a stronger status;
    it will be overwritten regardless of what you write.
  - A proposed invariant is not a finding. Do not write it as if a
    vulnerability were confirmed — you are stating an obligation the
    architecture must satisfy, not an observed violation.
  - Bind every invariant to concrete architecture_refs (element/relation
    IDs from the ArchitectureModel you were given) wherever you can — an
    invariant that names no real element/relation from this project's own
    model is not project-specific, it is generic TWE prose restated.
  - If a project-specific obligation genuinely fits no existing TWE in
    the prior-knowledge context, still emit it, but say so explicitly in
    unresolved_assumptions (e.g. "no existing TWE playbook covers this
    obligation — catalog gap").
  - Do not claim an attestation/verification/rollback-check API already
    satisfies an invariant purely because its name suggests it should —
    if you have not seen the actual enforcement code, say so in
    unresolved_assumptions and verification_plan rather than asserting
    the property holds.
  - verification_plan must name concrete, checkable steps — name the
    actual function, field and call site you want traced, in this
    project's own vocabulary — not vague reassurance ("ensure proper
    validation"). No example is given here on purpose: the previous one
    spelled out a benchmark case's answer, so any run on that case was
    reading the solution out of its own system prompt.

Respond with a single JSON object: { "invariants": [ ... ] }. Each entry:
  { "invariant_id": "INV-<TOPIC>-NNN", "statement": "...",
    "related_twes": ["TWE-..."], "parties": [...], "assets": [...],
    "boundaries": [...], "entrypoints": [...], "authority_points": [...],
    "required_properties": [...], "expected_defenses": [...],
    "architecture_refs": ["<element or relation id from the model>"],
    "verification_plan": ["..."], "unresolved_assumptions": [...],
    "evidence": [ { "kind": "source", "file": "...", "start_line": N,
                     "end_line": N, "note": "<symbol this cites>" } ] }`

// buildUserPrompt renders the per-run context: TWE prior knowledge and the
// already-validated ArchitectureModel (condensed).
func buildUserPrompt(in Input) string {
	return fmt.Sprintf(`## TWE prior knowledge

%s

## Architecture Model (already validated; architecture_refs must point at real ids from here)

%s

## Instructions

Derive a small set of project-specific invariants by instantiating the
TWE scenarios above against this specific architecture. Every invariant
is proposed only — see the rules in the system prompt.`,
		nonEmpty(in.TWEContext, "(no TWE prior knowledge context available for this run)"),
		marshalCondensed(in.Model, 8000))
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
