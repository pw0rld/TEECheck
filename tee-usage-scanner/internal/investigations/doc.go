// Package investigations builds and grounds artifacts.TWEInvestigation
// (§9.5 of the merge design) — the Planner's structured, still-reviewable
// application of one or more TWE playbooks to the current project (§7.5,
// §24).
//
// The package's job is deliberately narrow and non-conclusive: it never
// decides whether a repository is vulnerable or safe. §7.5 is explicit that
// the Investigator/Planner "不负责最终漏洞结论" (does not own the final
// vulnerability conclusion) and that a missing role is the Planner's NEXT
// TASK, not a finding — artifacts.TWEInvestigation itself has no verdict
// field, so nothing built here can carry one. What this package does own:
//
//   - Build turns a loosely-typed WireInvestigation (what the Planner LLM,
//     or any other caller, declares it observed) into the canonical
//     artifacts.TWEInvestigation shape: it classifies standard vs. variant
//     vs. composition vs. catalog_gap from the structural shape of the
//     matched TWE IDs (0 → catalog_gap, >1 → composition, 1 → the caller's
//     standard/variant opinion), normalizes filled/missing roles, and
//     derives a deterministic investigation ID.
//   - Validate grounds every reference an investigation makes — to the
//     ArchitectureModel, to the current ProjectInvariants, to a persisted
//     ToolFact, and to a real file under the repository — dropping (and
//     recording as an Adjustment) anything that does not resolve. This is
//     the same "invented references get stripped, not trusted" discipline
//     internal/architecture and internal/invariants already apply to their
//     own artifacts.
//   - AttackChainComplete reports the structural precondition for treating
//     an investigation's observed_flow as a demonstrated attack path: every
//     role is filled and every playbook-required evidence item is
//     satisfied. This is the "attack-chain completeness check" §24 asks
//     for — it is a necessary, not sufficient, condition; Expert/
//     Challenger/Verifier (PR-07, out of this package's scope) still make
//     the actual vulnerability call on top of it.
//   - BuildCasePack renders the bounded Case Pack (§24 "Case Pack 修改") for
//     one investigation: related TWE/invariant IDs, architecture and
//     ToolFact refs, outstanding required evidence, missing links, the
//     matched playbook's common defenses/false positives, and coverage
//     gaps — everything Expert/Challenger need without re-deriving it or
//     re-reading the full TWE catalog / Architecture Model.
package investigations
