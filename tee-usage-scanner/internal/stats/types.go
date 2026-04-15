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

	Planner    PlannerStats    `json:"planner"`
	Cases      CasesStats      `json:"cases"`
	Expert     ExpertStats     `json:"expert"`
	Challenger ChallengerStats `json:"challenger"`
	Verifier   VerifierStats   `json:"verifier"`
	Arbiter    ArbiterStats    `json:"arbiter"`
	Overall    OverallStats    `json:"overall"`
}

// PlannerStats aggregates signals from 04_planner/.
type PlannerStats struct {
	Present             bool           `json:"present"`
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
type ExpertStats struct {
	Present            bool    `json:"present"`
	HypothesisCount    int     `json:"hypothesis_count"`
	CitationRate       float64 `json:"citation_rate"`
	HypothesisLenP50   int     `json:"hypothesis_length_p50"`
	HypothesisLenMean  int     `json:"hypothesis_length_mean"`
	SupportingFactsP50 int     `json:"supporting_facts_p50"`
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
