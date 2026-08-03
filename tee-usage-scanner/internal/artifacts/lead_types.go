package artifacts

// AuditLead is a question the Planner decided to ask about this project's
// own code (ARCHITECTURE.md §6.2).
//
// It is a question, not a finding. The distinction is the whole point: 01
// produces no security anchors, and calling the Planner's current target an
// "anchor" is what let BUG-003's chain run — a keyword match became a
// freshness candidate, became an architecture asset, became an invariant
// anchored at a line nobody had read, and every stage downstream treated the
// last one as established fact.
//
// What keeps a lead from becoming that is ReasonFactRefs: every reason must
// point at an observation the Planner actually made in this sample. A lead
// that cannot cite is refused rather than downgraded.
type AuditLead struct {
	SchemaVersion string `json:"schema_version"`
	LeadID        string `json:"lead_id"`
	RunID         string `json:"run_id"`
	// SampleIndex is which --samples pass raised this lead. Its
	// ReasonFactRefs resolve only within that pass: every pass restarts at
	// round 1, and two passes are pointed at different code on purpose.
	SampleIndex   int `json:"sample_index"`
	OpenedAtRound int `json:"opened_at_round"`

	// TargetSymbolIDs are the definitions the question is about, by id
	// rather than by name. Two files can each define a static function of
	// the same name, so a name does not identify a target.
	TargetSymbolIDs  []SymbolID `json:"target_symbol_ids"`
	SecurityQuestion string     `json:"security_question"`

	// Reason and ReasonFactRefs are parallel: reason[i] is grounded by the
	// observation ReasonFactRefs names. Free-text reasons with no ref are
	// what this type exists to refuse.
	Reason         []string `json:"reason"`
	ReasonFactRefs []string `json:"reason_fact_refs"`

	// RequestedContext is what the Planner wants to expand next
	// (body:, callers:, def-use:), per §6.2. It is a plan, not evidence.
	RequestedContext []string `json:"requested_context,omitempty"`

	// Uncertainty is the Planner's own confidence that the question is
	// worth answering — low, medium or high. High is not a severity.
	Uncertainty string `json:"uncertainty,omitempty"`

	// State follows §6.2: open, expanded, formalized, closed.
	State string `json:"state"`

	// RelatedTWEs may be empty, and §6.4 requires that it may: a question
	// with no catalog mapping must still be investigable. A lead is not
	// less real for describing a break this project has that no playbook
	// names.
	RelatedTWEs []string `json:"related_twes,omitempty"`
}

// Lead states (§6.2).
const (
	LeadStateOpen       = "open"
	LeadStateExpanded   = "expanded"
	LeadStateFormalized = "formalized"
	LeadStateClosed     = "closed"
)

// CoverageLedger records what the Planner looked at and, more importantly,
// what it did not (ARCHITECTURE.md §6.5).
//
// It exists because an LLM left alone opens the functions whose names
// contain verify, auth and crypto. Anything not selected is recorded here as
// a coverage gap; §6.5 is explicit that it may never be read as an absence
// of risk.
//
// One ledger per run, with a per-sample breakdown rather than one file per
// sample: the samples are unioned by every downstream consumer, and a
// per-sample file would make each of them re-aggregate.
type CoverageLedger struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`

	ModulesTotal             int `json:"modules_total"`
	ModulesReviewed          int `json:"modules_reviewed"`
	FunctionCapsulesTotal    int `json:"function_capsules_total"`
	FunctionCapsulesReviewed int `json:"function_capsules_reviewed"`

	// UnreviewedClusters names the modules with no viewed capsule. It is
	// written even when it is long — an omitted list reads as "nothing was
	// missed", which is the opposite of what a long one means.
	UnreviewedClusters []string `json:"unreviewed_clusters"`

	LeadsOpen int `json:"leads_open"`

	// BySample is each pass's own contribution. The totals above are the
	// union across passes, which is not their sum: two passes that opened
	// the same module reviewed one module, not two.
	BySample []SampleCoverage `json:"by_sample"`
}

// SampleCoverage is one --samples pass's share of the ledger.
type SampleCoverage struct {
	SampleIndex int `json:"sample_index"`
	// ReconMode is which gate this pass was held to: indexed, tree_only or
	// unavailable. A pass with no program index browsed nothing, and its
	// zero counts mean that rather than a pass that read nothing.
	ReconMode string `json:"recon_mode"`
	// ReconStatus is how the pass left reconnaissance: satisfied,
	// budget_exhausted or incomplete. A run that finished gated must stay
	// distinguishable from one that finished.
	ReconStatus        string   `json:"recon_status"`
	ModulesReviewed    []string `json:"modules_reviewed"`
	CapsulesReviewed   int      `json:"capsules_reviewed"`
	FilesRead          int      `json:"files_read"`
	RelationQueriesRun int      `json:"relation_queries_run"`
	RoundsUsed         int      `json:"rounds_used"`
	ReconRoundsUsed    int      `json:"recon_rounds_used"`
	LeadsOpened        int      `json:"leads_opened"`
}
