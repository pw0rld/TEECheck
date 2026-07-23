// Package architecture implements the Architecture Agent (§7.3, §22 of the
// merge design). It turns a ProjectProfileV2 fingerprint plus TWE prior
// knowledge into a structured ArchitectureModel — parties, components,
// roles, assets, trust zones, boundaries, entrypoints, data flows, state
// lifecycles, trust/deployment assumptions and unknowns — with a derived
// Markdown dossier. The JSON model is the authoritative artifact; the
// dossier (RenderDossier) is a presentation view generated from it, never a
// second source of truth (§9.2).
//
// # The citation validator
//
// §22 calls out one mechanism as "the one thing stopping the LLM from
// inventing architecture": every observed/documented statement's evidence
// must actually resolve against the live repo, and the resolved bytes must
// actually contain the symbol the statement claims. ValidateAndDowngrade is
// that mechanism. It is deliberately built on top of internal/citations
// (Resolve) rather than as a second, parallel validator — see the two
// subsections below for how the two contracts are bridged and why the
// symbol check needed one small addition beyond what citations already does.
//
// # Bridging EvidenceReference and citations.CitedBytes
//
// artifacts.EvidenceReference (the §9.2 contract) has File/StartLine/EndLine
// but no recorded hash; citations.CitedBytes (the existing validator's unit)
// additionally carries StartByte/EndByte/SHA256 so a later run can detect
// that cited bytes drifted since they were first cited. Two ways to close
// that gap were on the table:
//
//   - (a) chosen: EvidenceReference.CitedBytes() (internal/artifacts) does a
//     hash-free conversion — File/StartLine/EndLine only. citations.Resolve
//     re-reads the file and derives StartByte/EndByte/SHA256 fresh, every
//     time ValidateAndDowngrade runs. This still catches everything a
//     forged or careless citation can get wrong within a single run — a
//     nonexistent file, an out-of-range line, a line range that resolves to
//     bytes not containing the claimed symbol — because Resolve has to
//     re-derive the region from disk regardless of whether a prior hash was
//     recorded. What it cannot do is prove the repo has not changed
//     *between* two separate validation passes, because there is no first
//     hash to compare a second one against.
//   - (b) not chosen: add a SHA256 field to EvidenceReference itself. This
//     would require a schema change to both schemas/architecture.v1.json
//     and its byte-identical embedded copy under internal/schema/schemas/,
//     for a property this PR does not need: within one Architecture Agent
//     run the repository checkout is immutable (nothing in this pipeline
//     mutates the working tree mid-run), so "did the cited bytes change
//     since I cited them ten seconds ago in the same process" is not a
//     question that arises here. Drift detection matters across runs (a
//     stale ArchitectureModel read back days later) — that is a real future
//     need, but not one §22 asks PR-04 to solve, and adding an unused field
//     to a frozen contract is a cost paid by every future PR that touches
//     architecture.v1.json for no present benefit.
//
// (a) is implemented as EvidenceReference.CitedBytes() in
// internal/artifacts/merge_types.go, next to the contract it converts.
//
// # The symbol check
//
// citations.Resolve/Validate only prove a citation's line range exists and
// hash-matches; they say nothing about content. §22 requires more: "the
// cited location actually contains the declared symbol, not just that the
// file exists." EvidenceReference has no dedicated "symbol" field (the
// schema is frozen for this PR — see the package-level note in
// internal/invariants for the analogous gap on ProjectInvariant), so this
// package uses EvidenceReference.Note as the symbol the citation is meant to
// prove, falling back to the owning ArchitectureElement's Name when Note is
// empty. ArchitectureRelation has no comparable name-shaped field (From/To
// are internal element IDs, not source tokens), so relation evidence gets
// the existence+range check but not the symbol check — see checkEvidence's
// doc comment and the final PR report for this as a named, surfaced gap
// rather than a silently-skipped one.
package architecture
