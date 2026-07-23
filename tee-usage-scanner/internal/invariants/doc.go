// Package invariants implements the Invariant Agent (§7.4, §22 of the merge
// design). It takes the full TWE prior-knowledge context, the
// ArchitectureModel the Architecture Agent already produced and validated,
// and ProjectProfile evidence, and instantiates general TWE scenarios into
// project-specific ProjectInvariant obligations — each with status
// "proposed" and a concrete verification_plan.
//
// # Status can only ever be "proposed" out of this package
// (§3.4: "Invariant 初始状态只能是 proposed。只有后续工具和 Agent 调查才能将其
// 更新为 grounded/satisfied/violated_candidate/unresolved 或有证据支持的
// not_applicable"). EnforceProposedStatus (validate.go) overwrites whatever
// the model returned before persistence — this package has no code path
// that reads a Verifier/Arbiter-style status back in, and no code path that
// produces an artifacts.UnifiedFindingV3 at all, so a proposed invariant
// structurally cannot reach the finding surface from here (§15.6, §22:
// "不允许把 proposed invariant 直接输出为 finding").
//
// # The catalog_gap schema gap
//
// §7.4 requires: "允许生成无法归入现有 TWE 的 project-specific invariant 并
// 标记 catalog gap". TWEInvestigation (§9.5) has a first-class
// `classification: standard|variant|composition|catalog_gap` field for
// exactly this. ProjectInvariant (§9.3) does not — and its schema requires
// `related_twes` to be present AND non-empty (`minItems: 1`), which makes
// "this invariant maps to zero TWEs" schema-illegal to state directly.
//
// This package resolves the tension with CatalogGapTWEID, a sentinel value
// ("TWE-CATALOG-GAP") used as the sole related_twes entry when no real
// playbook fits, paired with an UnresolvedAssumptions entry that says so in
// plain text. This satisfies the frozen schema and keeps the catalog-gap
// signal machine-detectable (grep related_twes for the sentinel) without
// silently forcing a real, wrong TWE ID onto an obligation that does not
// actually match any playbook. It is a workaround for a genuine schema gap,
// not a first-class solution — see this PR's final report for the
// surfaced recommendation (a `classification` field on ProjectInvariant,
// mirroring TWEInvestigation, in a future schema revision).
package invariants
