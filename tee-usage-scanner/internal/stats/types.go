package stats

// RunStats is the top-level aggregated view of a single TEECheck run.
// It is computed on-demand by Collect() from the on-disk artifacts
// under runs/<run-id>/; nothing in the pipeline writes it during the
// run itself, so it can be recomputed retroactively for any historical
// run directory.
type RunStats struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	RunDir        string `json:"run_dir"`

	// Source labels which input drove the metrics:
	//   - "events"    : every populated stage was derived from events.jsonl
	//   - "artifacts" : no events.jsonl available; everything came from
	//                   stage JSON files (rounds.jsonl, evidence_bundle.json,
	//                   hypothesis-*.json, etc.)
	//   - "mixed"     : some stages used events, others used artifacts —
	//                   currently the typical case, since only the planner
	//                   is event-instrumented (commit 2). Other agents
	//                   continue to come from stage JSON until they are
	//                   wired to events in later commits.
	Source string `json:"source,omitempty"`

	Planner    PlannerStats    `json:"planner"`
	Cases      CasesStats      `json:"cases"`
	Expert     ExpertStats     `json:"expert"`
	Challenger ChallengerStats `json:"challenger"`
	Verifier   VerifierStats   `json:"verifier"`
	Arbiter    ArbiterStats    `json:"arbiter"`
	Review     ReviewStats     `json:"review,omitempty"`
	Overall    OverallStats    `json:"overall"`
}

// PlannerStats aggregates signals from 04_planner/.
//
// Source labels which on-disk input the metrics were folded from:
//   - "events"    : events.jsonl supplied rounds_used, tokens_used,
//                   tokens_by_round, action_mix; the rest came from
//                   evidence_bundle.json (which still owns candidates,
//                   path/symbol validity, diversity, termination reason)
//   - "artifacts" : no events.jsonl available (legacy run); folded
//                   from rounds.jsonl + evidence_bundle.json
type PlannerStats struct {
	Present             bool           `json:"present"`
	Source              string         `json:"source,omitempty"`
	CandidateCount      int            `json:"candidate_count"`
	PathValidityRate    float64        `json:"path_validity_rate"`
	SymbolValidityRate  float64        `json:"symbol_validity_rate"`
	TerminationReason   string         `json:"termination_reason"`
	RoundsUsed          int            `json:"rounds_used"`
	RoundsBudget        int            `json:"rounds_budget"`
	DiversityIndex      int            `json:"diversity_index"`
	ActionMix           map[string]int `json:"action_mix"`
	TokensUsed          int            `json:"tokens_used"`
	TokensByRound       []int          `json:"tokens_by_round"`
	WallClockMs         int64          `json:"wall_clock_ms"`
	HallucinatedPaths   []string       `json:"hallucinated_paths,omitempty"`
	HallucinatedSymbols []string       `json:"hallucinated_symbols,omitempty"`
}

// CasesStats aggregates signals from 03_cases/.
type CasesStats struct {
	Present              bool    `json:"present"`
	CaseCount            int     `json:"case_count"`
	SymbolCoverageRate   float64 `json:"symbol_coverage_rate"`
	SnippetLineTotalP50  int     `json:"snippet_line_total_p50"`
	SnippetLineTotalMean int     `json:"snippet_line_total_mean"`
	ObligationsAttached  int     `json:"obligations_attached"`
}

// ExpertStats aggregates signals from 04_expert/.
//
// CitationRate semantics changed in the A1 byte-citation work:
//   - Before: regex match for "file.rs:42" substrings in summary +
//     supporting_facts. Counted any line-number-shaped string,
//     never validated against the repo.
//   - Now: fraction of hypotheses whose Cited list is non-empty AND
//     contains at least one CitedBytes that successfully validates
//     against the repo (file present, line range resolvable, sha256
//     either matches or is unset for legacy entries).
//
// Legacy hypotheses that pre-date the citation contract have no
// Cited field, so they show CitationRate = 0. That is the right
// answer — they were not in fact citing.
type ExpertStats struct {
	Present              bool    `json:"present"`
	HypothesisCount      int     `json:"hypothesis_count"`
	CitationRate         float64 `json:"citation_rate"`
	CitationValidityRate float64 `json:"citation_validity_rate"`
	HypothesisLenP50     int     `json:"hypothesis_length_p50"`
	HypothesisLenMean    int     `json:"hypothesis_length_mean"`
	SupportingFactsP50   int     `json:"supporting_facts_p50"`
}

// ChallengerStats aggregates signals from 05_challenger/.
type ChallengerStats struct {
	Present              bool    `json:"present"`
	ChallengeCount       int     `json:"challenge_count"`
	NonRubberStampRate   float64 `json:"non_rubber_stamp_rate"`
	CounterArgsP50       int     `json:"counter_arguments_p50"`
	RemainingQuestionsP50 int    `json:"remaining_questions_p50"`
}

// VerifierStats aggregates signals from 06_verifier/.
type VerifierStats struct {
	Present            bool           `json:"present"`
	MemoCount          int            `json:"memo_count"`
	StatusDistribution map[string]int `json:"status_distribution"`
	CorroborationRate  float64        `json:"corroboration_rate"`
	ConfirmedFactsP50  int            `json:"confirmed_facts_p50"`
	ContradictionsP50  int            `json:"contradictions_p50"`
}

// ArbiterStats aggregates signals from 07_arbiter/.
type ArbiterStats struct {
	Present               bool           `json:"present"`
	FindingCount          int            `json:"finding_count"`
	StatusDistribution    map[string]int `json:"status_distribution"`
	ConfidenceDistribution map[string]int `json:"confidence_distribution"`
	SeverityDistribution  map[string]int `json:"severity_distribution"`
	VerifierAgreementRate float64        `json:"verifier_agreement_rate"`
	PacketWordcountP50    int            `json:"packet_wordcount_p50"`
}

// ReviewStats aggregates human ground-truth labels from
// 08_review/review_records.jsonl. Empty / Present=false when the
// run has not been reviewed yet — the typical state for fresh
// dogfood data.
//
// C1 keeps the Phase 1 shape (TPCount/FPCount/NMCCount/SkipCount +
// FPRate) so the schema swap stays a no-op refactor. C3 replaces
// these with verdict_counts + three explicit rate metrics
// (fp_rate_definitive / fp_rate_reviewed / non_tp_rate_reviewed)
// and switches by_citation_validity to a 5-bucket discriminator.
//
// Slices: ByCategory keys are the case category fields
// (attestation / authorization / boundary / ...). ByArbiterStatus
// keys are findings.json status values (no_issue_observed /
// needs_review / likely_issue / confirmed_candidate).
// ByCitationValidity buckets are currently "validated" / "unanchored"
// — the 5-bucket cross-tab arrives in C3.
//
// ReasonCodes counts the reason_code distribution. C1 reads it from
// ReviewRecord.EffectiveReasonCode() so legacy fp_reason values
// keep flowing through unchanged.
type ReviewStats struct {
	Present              bool                       `json:"present"`
	TotalReviewed        int                        `json:"total_reviewed"`
	TPCount              int                        `json:"tp_count"`
	FPCount              int                        `json:"fp_count"`
	NMCCount             int                        `json:"nmc_count"`
	SkipCount            int                        `json:"skip_count"`
	FPRate               float64                    `json:"fp_rate"`
	ByCategory           map[string]ReviewBucketAgg `json:"by_category,omitempty"`
	ByArbiterStatus      map[string]ReviewBucketAgg `json:"by_arbiter_status,omitempty"`
	ByCitationValidity   map[string]ReviewBucketAgg `json:"by_citation_validity,omitempty"`
	ReasonCodes          map[string]int             `json:"reason_codes,omitempty"`
}

// ReviewBucketAgg is the per-slice TP/FP/NMC count for one bucket.
type ReviewBucketAgg struct {
	TP     int     `json:"tp"`
	FP     int     `json:"fp"`
	NMC    int     `json:"nmc"`
	Total  int     `json:"total"`
	FPRate float64 `json:"fp_rate"`
}

// OverallStats ties the stage counts together.
type OverallStats struct {
	PipelineYield       float64 `json:"pipeline_yield"`
	CostPerCorroborated int     `json:"cost_per_corroborated"`
	Dropoff             Dropoff `json:"dropoff"`
}

// Dropoff is the per-stage count of artifacts that made it through.
// Useful for plotting a funnel.
type Dropoff struct {
	Candidates  int `json:"candidates"`
	Cases       int `json:"cases"`
	Hypotheses  int `json:"hypotheses"`
	Challenges  int `json:"challenges"`
	Verifies    int `json:"verifies"`
	Findings    int `json:"findings"`
	Corroborated int `json:"corroborated"`
}
