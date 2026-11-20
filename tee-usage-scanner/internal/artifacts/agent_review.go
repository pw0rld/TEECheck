package artifacts

// This file holds the PR-07 additive types that extend the Expert →
// Challenger → Verifier → Arbiter chain (§7.6-§7.9, §25) so the four
// review agents can consume the Architecture Model, Project
// Invariants, and ToolFacts alongside the Case Pack, and so the
// Challenger's independent (phase-1) judgment survives as its own
// artifact rather than being folded silently into the final
// Challenge. None of these types carry a JSON schema today (unlike
// ArchitectureModel/ProjectInvariant/ToolFact/CasePack) — same
// convention Hypothesis/Challenge/VerificationMemo/FindingItem
// already follow.

// ChallengerIndependentView is the Challenger's phase-1 output (§7.7,
// §25): a judgment formed from TWE knowledge, the case's Architecture
// slice and Invariants, and the Case Pack's raw source/tool facts —
// WITHOUT reading the Expert's Hypothesis. It is persisted to its own
// file (independent-NNN.json) before phase 2 ever loads the
// hypothesis, so a test can inspect the phase-1 prompt/inputs in
// isolation and prove they never carried the Expert's conclusion.
//
// Known limitation (§7.7, carried over verbatim per the spec's
// instruction not to overclaim independence): the ToolFacts phase 1
// sees are themselves the product of the Expert/Planner's earlier
// investigation choices, so this is independence-of-conclusion, not
// independence-of-evidence-selection. v1 does not solve this; it is
// recorded in KnownLimitations so it isn't silently forgotten once
// the phase-1-prompt-exclusion test passes.
type ChallengerIndependentView struct {
	ContractReviews []ContractReview `json:"contract_reviews,omitempty"`
	SchemaVersion   string           `json:"schema_version"`
	CaseID          string           `json:"case_id"`
	AgentID         string           `json:"agent_id"`

	// IssuePresent is the phase-1 independent verdict: does the
	// evidence visible to phase 1 (TWE knowledge + architecture slice
	// + invariants + case pack source/tool facts) show a real
	// problem, judged without seeing what the Expert concluded.
	IssuePresent bool   `json:"issue_present"`
	Reasoning    string `json:"reasoning"`

	// DefensesConsidered records wrapper/lower-layer/external-service
	// protections and the TWE's common_defenses / common_false_positives
	// the Challenger checked for (§7.7).
	DefensesConsidered []string `json:"defenses_considered,omitempty"`

	// CounterExamples are tool-verifiable alternative explanations
	// found in phase 1 (§7.7: "提出可以被工具验证的反例").
	CounterExamples []string `json:"counter_examples,omitempty"`

	Confidence string `json:"confidence"`

	// KnownLimitations documents independence caveats that apply to
	// this specific run (e.g. the ToolFacts-shaped-by-Expert caveat
	// above). Not a confession of failure — a disclosed scope limit.
	KnownLimitations []string `json:"known_limitations,omitempty"`
}

// InvariantStatusUpdate is the Verifier's proposed change to a
// ProjectInvariant's verification status (§7.8). Per §3.5 ("追加，
// 而不是覆盖"), the Verifier package never rewrites
// project_invariants.v1.json in place — these updates are appended to
// a separate log (see runfs paths under VerifierDir) and carried on
// the VerificationMemo, so the original `proposed` artifact the
// Invariant Agent wrote stays exactly as it was.
type InvariantStatusUpdate struct {
	InvariantID    string `json:"invariant_id"`
	PreviousStatus string `json:"previous_status"`
	// NewStatus follows the same vocabulary as
	// schemas/project-invariant.v1.json's status enum (proposed,
	// grounded, satisfied, violated_candidate, unresolved,
	// not_applicable) even though this record is not itself
	// schema-validated — consumers that fold it back into a
	// ProjectInvariant expect the same values.
	NewStatus string `json:"new_status"`
	Reason    string `json:"reason,omitempty"`
}

// Evidence outcome vocabulary for EvidenceDistinctionNote.Outcome —
// §7.8's "区分「未找到」与「证明不存在」" (distinguish "not found" from
// "proven absent").
const (
	// EvidenceNotFound means the tool layer was asked and returned no
	// match, but nothing ran an exhaustive/authoritative check — the
	// property might still hold, we simply didn't see it.
	EvidenceNotFound = "not_found"
	// EvidenceProvenAbsent means a tool call that enumerates
	// exhaustively (e.g. a fact-layer query with no coverage gaps and
	// no truncation) ran and affirmatively found zero matches — the
	// property is verified absent, not merely unseen.
	EvidenceProvenAbsent = "proven_absent"
)

// EvidenceDistinctionNote records, for one disputed claim, whether the
// Verifier merely failed to find corroborating evidence or actually
// proved the property's absence.
type EvidenceDistinctionNote struct {
	Claim   string `json:"claim"`
	Outcome string `json:"outcome"`
	Note    string `json:"note,omitempty"`
}

// ArbiterSections is the machine-readable counterpart to the arbiter
// review packet Markdown (§7.9, §25): explicitly separated sections
// so a consumer never has to re-parse Markdown headings to tell
// anchored tool facts apart from Agent assessments. The Markdown
// packet (review-NNN.md) remains the human-facing rendering of the
// same underlying data.
type ArbiterSections struct {
	AnchoredToolFacts           []string `json:"anchored_tool_facts,omitempty"`
	ArchitectureEvidenceStatus  []string `json:"architecture_evidence_status,omitempty"`
	InvariantVerificationStatus []string `json:"invariant_verification_status,omitempty"`
	ExpertHypothesis            string   `json:"expert_hypothesis,omitempty"`
	IndependentChallengerResult string   `json:"independent_challenger_result,omitempty"`
	VerifierResolution          string   `json:"verifier_resolution,omitempty"`
	RemainingCoverageGaps       []string `json:"remaining_coverage_gaps,omitempty"`
	HumanReviewQuestions        []string `json:"human_review_questions,omitempty"`
}
