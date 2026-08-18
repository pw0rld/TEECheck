package artifacts

import (
	"encoding/json"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	RepoURL       string `json:"repo_url"`
	LocalPath     string `json:"local_path"`
	Commit        string `json:"commit"`
	Focus         string `json:"focus"`
	// Hint is the free-text concern the caller supplied ("I suspect the TA
	// loading path"). It is recorded here, not only passed to the planner,
	// because a run's result cannot be read without knowing what the run was
	// told: the same finding means something different when the caller
	// already named the subsystem. For a benchmark run it is the difference
	// between measuring discovery and measuring recognition, so it has to be
	// on the record rather than in the invocation someone has to remember.
	Hint string `json:"hint,omitempty"`
	// Scope is the one tree every stage of the run reads, recorded once so
	// each consumer can check it is reading the same one. On CVE-2026-44362
	// the fact layer analysed a full checkout while reverse_trace read a
	// four-file fixture, and the Challenger concluded the code was
	// unreachable — no artifact stated the disagreement, so nothing could
	// detect it.
	Scope         ScannedScope      `json:"scope,omitempty"`
	CreatedAt     string            `json:"created_at"`
	ToolVersions  map[string]string `json:"tool_versions,omitempty"`
	Build         *BuildProvenance  `json:"build,omitempty"`
	Configuration *RunConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
}

// BuildProvenance identifies the scanner binary that produced a run. Unknown
// values are represented explicitly rather than replaced with release-like
// constants that cannot be verified.
type BuildProvenance struct {
	Version     string `json:"version"`
	GoVersion   string `json:"go_version"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSModified bool   `json:"vcs_modified,omitempty"`
}

// RunConfiguration records the resolved, secret-free controls that materially
// affect pipeline output.
type RunConfiguration struct {
	Command         string           `json:"command"`
	Mode            string           `json:"mode,omitempty"`
	Samples         int              `json:"samples,omitempty"`
	MaxCases        int              `json:"max_cases,omitempty"`
	MaxHotspots     int              `json:"max_hotspots,omitempty"`
	MaxDialogRounds int              `json:"max_dialog_rounds,omitempty"`
	StaticTools     string           `json:"static_tools,omitempty"`
	LLM             LLMConfiguration `json:"llm"`
	Planner         *PlannerLimits   `json:"planner,omitempty"`
}

type LLMConfiguration struct {
	Provider        string  `json:"provider"`
	BaseURL         string  `json:"base_url,omitempty"`
	Model           string  `json:"model,omitempty"`
	Transport       string  `json:"transport"`
	ReasoningEffort string  `json:"reasoning_effort,omitempty"`
	TimeoutSeconds  int     `json:"timeout_seconds,omitempty"`
	MaxOutputTokens int     `json:"max_output_tokens,omitempty"`
	Temperature     float64 `json:"temperature"`
	APIKeyPresent   bool    `json:"api_key_present"`
}

type PlannerLimits struct {
	MaxInvestigationRounds int   `json:"max_investigation_rounds"`
	MaxReconRounds         int   `json:"max_recon_rounds"`
	MaxAggregateTokens     int   `json:"max_aggregate_tokens"`
	PerActionTimeoutMs     int64 `json:"per_action_timeout_ms"`
	WallClockTimeoutMs     int64 `json:"wall_clock_timeout_ms"`
}

// ScannedScope identifies the source tree a run actually read.
//
// Hash is derived from the repository identity and the file count rather
// than from the root path: the root lives under the run directory and
// therefore differs between two runs of the same revision, which would make
// every comparison fail. What it does detect is the case that matters — two
// stages reading trees that hold different amounts of code. It cannot detect
// two trees with the same identity and the same file count but different
// bytes; a stage that needs that guarantee must compare content itself.
type ScannedScope struct {
	RepoURL   string `json:"repo_url,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Root      string `json:"root,omitempty"`
	FileCount int    `json:"file_count,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

type RepoMap struct {
	SchemaVersion    string             `json:"schema_version"`
	Repo             RepoRef            `json:"repo"`
	Modules          []Module           `json:"modules"`
	Entrypoints      []Entrypoint       `json:"entrypoints"`
	Boundaries       []Boundary         `json:"boundaries"`
	ImportantFiles   []ImportantFile    `json:"important_files"`
	ImportantSymbols []ImportantSymbol  `json:"important_symbols"`
	CrossLangLinks   []CrossLanguageRef `json:"cross_language_links"`
	Notes            []string           `json:"notes,omitempty"`
}

type RepoRef struct {
	URL    string `json:"url"`
	Commit string `json:"commit"`
	Focus  string `json:"focus"`
}

type Module struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Paths       []string `json:"paths"`
	Description string   `json:"description,omitempty"`
}

type Entrypoint struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Symbol      string `json:"symbol,omitempty"`
	Description string `json:"description,omitempty"`
}

type Boundary struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Direction   string   `json:"direction"`
	Paths       []string `json:"paths"`
	Symbols     []string `json:"symbols,omitempty"`
	Description string   `json:"description,omitempty"`
}

type ImportantFile struct {
	Path     string   `json:"path"`
	Reasons  []string `json:"reasons"`
	Priority string   `json:"priority,omitempty"`
}

type ImportantSymbol struct {
	Path     string   `json:"path"`
	Symbol   string   `json:"symbol"`
	Reasons  []string `json:"reasons"`
	Priority string   `json:"priority,omitempty"`
}

type CrossLanguageRef struct {
	FromPath string `json:"from_path"`
	ToPath   string `json:"to_path"`
	Kind     string `json:"kind"`
}

type HotspotIndex struct {
	SchemaVersion string    `json:"schema_version"`
	RunID         string    `json:"run_id"`
	Hotspots      []Hotspot `json:"hotspots"`
}

type Hotspot struct {
	HotspotID   string   `json:"hotspot_id"`
	Kind        string   `json:"kind"`
	Priority    string   `json:"priority"`
	Paths       []string `json:"paths"`
	Symbols     []string `json:"symbols,omitempty"`
	WhySelected []string `json:"why_selected"`
}

type Findings struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	Findings      []FindingItem `json:"findings"`
}

type FindingItem struct {
	FindingID  string            `json:"finding_id"`
	SliceID    string            `json:"slice_id"`
	Status     string            `json:"status"`
	Severity   string            `json:"severity"`
	Confidence string            `json:"confidence"`
	Files      []string          `json:"files,omitempty"`
	Locations  []FindingLocation `json:"locations,omitempty"`
	Summary    string            `json:"summary"`
	Evidence   []string          `json:"evidence,omitempty"`

	// Sections is the additive (PR-07, §25/§7.9) machine-readable
	// counterpart to the arbiter review packet Markdown: anchored
	// ToolFacts, architecture evidence status, invariant verification
	// status, Expert hypothesis, independent Challenger result,
	// Verifier resolution, remaining coverage gaps, and human-review
	// questions, kept as clearly separated fields rather than prose a
	// consumer would have to re-parse.
	Sections *ArbiterSections `json:"sections,omitempty"`
}

// FindingLocation is the structured (file, line) position of a finding, so a
// consumer (the benchmark scorer) can match on line without parsing it out of
// the evidence prose. It carries the same data the evidence string embeds.
type FindingLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
}

type PromptSnippet struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Content   string `json:"content"`
}

type KnowledgeHint struct {
	Title  string   `json:"title"`
	Path   string   `json:"path"`
	Tags   []string `json:"tags,omitempty"`
	Reason string   `json:"reason"`
}

type CasePack struct {
	SchemaVersion       string          `json:"schema_version"`
	CaseID              string          `json:"case_id"`
	HotspotID           string          `json:"hotspot_id"`
	Focus               string          `json:"focus"`
	Category            string          `json:"category"`
	Priority            string          `json:"priority"`
	TargetFiles         []string        `json:"target_files,omitempty"`
	TargetSymbols       []string        `json:"target_symbols,omitempty"`
	WhySelected         []string        `json:"why_selected,omitempty"`
	ToolFacts           []string        `json:"tool_facts,omitempty"`
	GraphFacts          []string        `json:"graph_facts,omitempty"`
	Snippets            []PromptSnippet `json:"snippets,omitempty"`
	ExpectedObligations []string        `json:"expected_obligations,omitempty"`
	OpenQuestions       []string        `json:"open_questions,omitempty"`
	KnowledgeHints      []KnowledgeHint `json:"knowledge_hints,omitempty"`

	// The fields below are additive (PR-06, §24 "Case Pack 修改") — a Case
	// Pack produced from a TWEInvestigation carries the relevant slice of
	// project-understanding and TWE prior knowledge that motivated it,
	// rather than requiring Expert/Challenger to re-derive it. There is no
	// JSON schema for CasePack (unlike ArchitectureModel/ProjectInvariant/
	// ToolFact/TWEInvestigation), so these are plain additive Go fields.

	// RelatedTWEs mirrors TWEInvestigation.TWEIDs — the playbook(s) whose
	// scenario motivated this case.
	RelatedTWEs []string `json:"related_twes,omitempty"`
	// RelatedInvariants mirrors TWEInvestigation.InvariantIDs — the
	// project-specific obligations this case is evidence for or against.
	RelatedInvariants []string `json:"related_invariants,omitempty"`
	// ArchitectureRefs are stable IDs into the run's ArchitectureModel
	// (§11.3: the full model is persisted once; a Case Pack carries only
	// the relevant slice by reference, not a copy of the model).
	ArchitectureRefs []string `json:"architecture_refs,omitempty"`
	// ToolFactRefs are artifact paths to the ToolFacts (§9.6) this case's
	// evidence was built from. Distinct from the legacy free-text
	// ToolFacts field above — these are resolvable references, not prose.
	ToolFactRefs []string `json:"tool_fact_refs,omitempty"`
	// RequiredEvidence is the playbook's outstanding evidence checklist
	// for this investigation (mirrors TWEInvestigation.RequiredEvidence) —
	// what Expert/Challenger/Verifier still need to obtain or rule out.
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	// MissingLinks names the specific roles or evidence items the
	// Investigator could not yet locate — the "next task", not a
	// vulnerability or safety conclusion (§7.5).
	MissingLinks []string `json:"missing_links,omitempty"`
	// CommonDefenses and CommonFalsePositives are copied from the matched
	// TWE playbook(s) so downstream agents check them without re-reading
	// the full TWE catalog.
	CommonDefenses       []string `json:"common_defenses,omitempty"`
	CommonFalsePositives []string `json:"common_false_positives,omitempty"`
	// CoverageGaps mirrors TWEInvestigation.CoverageGaps — known,
	// disclosed limitations of this case's evidence, so a downstream
	// agent (or human reviewer) never mistakes silence for completeness.
	CoverageGaps []string `json:"coverage_gaps,omitempty"`
	// ObservedFlow mirrors TWEInvestigation.ObservedFlow — the ordered
	// attack path the Investigator actually traced, not a path anyone
	// re-derives downstream. Until 2026-07-28 it lived only in
	// 03_investigations/<id>.json, which no production reader opens, so
	// the single most specific thing an investigation produces never
	// reached Expert/Challenger/Verifier/Arbiter. Rendered into every
	// agent prompt via FormatToolPath.
	ObservedFlow []ToolPathStep `json:"observed_flow,omitempty"`
	// CounterEvidence mirrors TWEInvestigation.CounterEvidence — the
	// evidence the Investigator found AGAINST its own hypothesis. Same
	// history as ObservedFlow above. It is carried separately from
	// CommonFalsePositives (which is generic playbook prior knowledge):
	// this is what was observed in THIS repository.
	CounterEvidence []string `json:"counterevidence,omitempty"`
}

type Hypothesis struct {
	SchemaVersion      string   `json:"schema_version"`
	CaseID             string   `json:"case_id"`
	AgentID            string   `json:"agent_id"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	SuspectedIssue     string   `json:"suspected_issue"`
	MissingObligations []string `json:"missing_obligations,omitempty"`
	// SupportingFacts holds the validated free-text claims —
	// the Text of every CitedFact whose citations all resolved
	// against the live repo. Legacy hypotheses (pre-v1.1.1) used
	// this as the only fact field. v1.1.1+ should prefer CitedFacts
	// and treat SupportingFacts as a display fallback. Facts whose
	// citations failed to resolve are intentionally NOT mirrored
	// here, so consumers can distinguish "asserted + validated"
	// from "asserted only" at a glance.
	SupportingFacts []string `json:"supporting_facts,omitempty"`
	// CitedFacts is the v1.1.1 canonical fact field: each entry is
	// a free-text claim plus the byte regions backing it.
	// expert.Run calls citations.Resolve on each citation before
	// persistence and drops citations that fail. A fact may end up
	// with an empty Cited list — that's an acknowledged "asserted
	// but could not anchor" case, not promoted to SupportingFacts.
	CitedFacts []citations.CitedFact `json:"cited_facts,omitempty"`
	// UntypedFacts holds free-text context that was NOT validated:
	//   - legacy supporting_facts returned by an LLM that ignored
	//     the cited_facts schema
	//   - flattened tool hits (ripgrep matches injected by the
	//     expert pipeline) — useful context but not citation-anchored
	// V1.1.2 polish C2: kept separate from SupportingFacts so the
	// "validated facts" surface remains honest. Verifier prompt and
	// arbiter Evidence render these with an explicit [unanchored]
	// tag; they never silently merge with cited claims.
	UntypedFacts      []string        `json:"untyped_facts,omitempty"`
	KnowledgeHints    []KnowledgeHint `json:"knowledge_hints,omitempty"`
	Confidence        string          `json:"confidence"`
	NeedsVerification bool            `json:"needs_verification"`
	// Cited is the flat hypothesis-level citation pool. v1.1.1
	// populates it as the union of every citation across CitedFacts
	// (de-duplicated) so the older "Cited" reading path
	// (report rendering, legacy stats) keeps working during the
	// migration. Stats prefers CitedFacts when present; the Cited
	// field is the fallback for legacy hypotheses.
	Cited []citations.CitedBytes `json:"cited,omitempty"`

	// Classification mirrors TWEInvestigation.Classification /
	// ProjectInvariant.Classification (§7.6: "判断是标准 TWE、变体、组合
	// 还是 catalog gap"): standard | variant | composition |
	// catalog_gap. Empty means the expert did not classify (legacy
	// hypotheses, or a run that skips this judgment).
	Classification string `json:"classification,omitempty"`

	// AttackPremises lists the concrete preconditions the constructed
	// attack hypothesis depends on (§7.6: "列出攻击前提") — distinct
	// from MissingObligations, which names what the code fails to
	// enforce. A premise is something that must ALSO be true for the
	// attack to work (e.g. "attacker controls the sealed blob
	// storage", "no outer TLS termination strips this header").
	AttackPremises []string `json:"attack_premises,omitempty"`
}

type Challenge struct {
	SchemaVersion      string   `json:"schema_version"`
	CaseID             string   `json:"case_id"`
	AgentID            string   `json:"agent_id"`
	ExploitNarrative   string   `json:"exploit_narrative"`
	CounterArguments   []string `json:"counter_arguments,omitempty"`
	RemainingQuestions []string `json:"remaining_questions,omitempty"`
	SuggestedChecks    []string `json:"suggested_checks,omitempty"`
	Exploitability     string   `json:"exploitability"`
	ReviewerStance     string   `json:"reviewer_stance"`

	// The fields below are additive (PR-07, §25): the two-phase
	// Challenger persists its phase-1 independent judgment (see
	// ChallengerIndependentView) separately, then carries a summary of
	// it here alongside the actual differences found once phase 2
	// read the Expert hypothesis — the point of the two-phase design.

	// IndependentViewPath points at the persisted phase-1 artifact
	// (independent-NNN.json) so a reader can open the full,
	// hypothesis-blind judgment without re-deriving it.
	IndependentViewPath string `json:"independent_view_path,omitempty"`
	// IndependentIssuePresent mirrors ChallengerIndependentView.IssuePresent
	// at the moment phase 2 ran, so a consumer of Challenge alone
	// (without opening the phase-1 file) still sees the independent
	// verdict.
	IndependentIssuePresent bool `json:"independent_issue_present"`
	// KeyDifferences names where the independent (phase-1) view and
	// the Expert hypothesis actually disagree (§25 acceptance:
	// vulnerable/fixed variants must produce a recognizable
	// difference here).
	KeyDifferences []string `json:"key_differences,omitempty"`
}

type VerificationMemo struct {
	SchemaVersion string   `json:"schema_version"`
	CaseID        string   `json:"case_id"`
	AgentID       string   `json:"agent_id"`
	Status        string   `json:"status"`
	ChecksRun     []string `json:"checks_run,omitempty"`
	// ConfirmedFacts holds the validated free-text claims produced
	// by the verifier — the Text of every ConfirmedCitedFacts entry
	// whose citations all resolved against the live repo. Legacy
	// memos used this as the only confirmed-fact field. v1.1.2+
	// should prefer ConfirmedCitedFacts and treat ConfirmedFacts
	// as a display fallback. Same exclusion rule as expert: facts
	// whose citations failed are NOT mirrored here.
	ConfirmedFacts []string `json:"confirmed_facts,omitempty"`
	// CandidateFacts are structured static-tool candidates that have not
	// been independently confirmed by the verifier. They must not affect
	// the confirmed verdict or benchmark truth by themselves.
	CandidateFacts []string `json:"candidate_facts,omitempty"`
	// ConfirmedCitedFacts is the v1.1.2 canonical confirmed-fact
	// field. Each entry pairs a confirmation claim with the byte
	// regions backing it.
	ConfirmedCitedFacts []citations.CitedFact `json:"confirmed_cited_facts,omitempty"`
	// UntypedConfirmedFacts is the V1.1.2 polish C3 separation
	// channel for LLM responses that returned legacy text-only
	// confirmed_facts instead of the structured cited form. The
	// text is preserved (so it shows up in human review packets)
	// but tagged so it never silently joins the validated surface.
	UntypedConfirmedFacts []string `json:"untyped_confirmed_facts,omitempty"`
	// Contradictions holds the validated contradiction text. Same
	// dual-field semantics as ConfirmedFacts.
	Contradictions []string `json:"contradictions,omitempty"`
	// ContradictedCitedFacts is the v1.1.2 canonical contradiction
	// field with byte citations.
	ContradictedCitedFacts []citations.CitedFact `json:"contradicted_cited_facts,omitempty"`
	// UntypedContradictions is the contradiction equivalent of
	// UntypedConfirmedFacts — legacy text-only contradictions kept
	// separate from the validated surface.
	UntypedContradictions []string `json:"untyped_contradictions,omitempty"`
	Notes                 []string `json:"notes,omitempty"`
	// ExpertCitationValidation records the per-fact result of
	// running citations.ValidateFacts on hypothesis.CitedFacts at
	// the moment the verifier saw them. Status is one of
	// citations.StatusValid / Stale / Unanchored / Unresolved.
	// Persisted so report / arbiter / human review can later see
	// which expert claims still held when the verifier reviewed.
	ExpertCitationValidation []citations.CitationValidation `json:"expert_citation_validation,omitempty"`
	// Cited is the flat verifier-level citation pool. v1.1.2
	// populates it as the deduplicated union of every citation
	// across ConfirmedCitedFacts and ContradictedCitedFacts.
	// Legacy memos that read Cited directly stay functional.
	Cited []citations.CitedBytes `json:"cited,omitempty"`

	// The fields below are additive (PR-07, §25/§7.8).

	// InvariantUpdates records the Verifier's proposed changes to
	// ProjectInvariant verification status for this case. Per §3.5
	// these are append-only: the Verifier package never rewrites
	// project_invariants.v1.json, it only appends to a log (see
	// runfs paths under VerifierDir) and mirrors the same entries
	// here so a reader of the memo sees them without opening the log.
	InvariantUpdates []InvariantStatusUpdate `json:"invariant_updates,omitempty"`

	// EvidenceDistinctions records, per disputed claim, whether the
	// Verifier merely found no corroborating evidence or actually
	// proved the property's absence (§7.8).
	EvidenceDistinctions []EvidenceDistinctionNote `json:"evidence_distinctions,omitempty"`

	// ArchitectureChecks and InvariantChecks are short text notes on
	// the architecture statements / invariants the Verifier consulted
	// while resolving this case's dispute — e.g. "boundary:tee-ta-001
	// is inferred, not observed; treated as unconfirmed" — so a
	// reader can see which project-understanding facts the Verifier's
	// judgment actually depended on.
	ArchitectureChecks []string `json:"architecture_checks,omitempty"`
	InvariantChecks    []string `json:"invariant_checks,omitempty"`
}

// ReviewRecord is the human ground-truth label attached to one
// arbiter finding. Phase 1.5 widened the verdict vocabulary to five
// non-skip values (TP / FP / needs_context / design_risk /
// no_issue_observed) and split the legacy FPReason field into a
// universal ReasonCode (applies to any non-TP verdict, see
// review.go).
type ReviewRecord struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	FindingID     string `json:"finding_id"`

	// Verdict is one of the Verdict* constants. NormalizeVerdict
	// accepts legacy values ("confirmed"/"dismissed"/"inconclusive"
	// /"needs_more_context").
	Verdict string `json:"verdict"`

	// ReasonCode is a Reason* taxonomy code explaining the failure
	// mode behind a non-TP verdict. Empty for TP and skip. Unknown
	// codes are stored verbatim for extensibility.
	ReasonCode string `json:"reason_code,omitempty"`

	// FPReason is the legacy Phase 1 field — kept for read
	// back-compat with any review_records.jsonl written between
	// 8ec877e and the Phase 1.5 schema bump. New writes use
	// ReasonCode; consumers should read EffectiveReasonCode().
	FPReason string `json:"fp_reason,omitempty"`

	// CorrectedSeverity is the reviewer's adjustment to the
	// arbiter's severity. Empty means "keep arbiter's value".
	CorrectedSeverity string `json:"corrected_severity,omitempty"`

	// ConfidenceOverride is the reviewer's adjustment to the
	// arbiter's confidence. Empty means "keep arbiter's value".
	ConfidenceOverride string `json:"confidence_override,omitempty"`

	// ReviewedEvidence is the subset of finding.Evidence the
	// reviewer affirmed they actually inspected. Empty means
	// "did not record per-evidence inspection".
	ReviewedEvidence []string `json:"reviewed_evidence,omitempty"`

	Tags  []string `json:"tags,omitempty"`
	Notes string   `json:"notes,omitempty"`

	// Severity is preserved for backward compatibility with old
	// review_records.jsonl. New writes set CorrectedSeverity
	// instead. Readers that want the human-corrected severity
	// should prefer CorrectedSeverity, falling back to Severity
	// for legacy records.
	Severity string `json:"severity,omitempty"`

	ReviewerID string `json:"reviewer_id,omitempty"`
	ReviewedAt string `json:"reviewed_at"`
}

// EvidenceBundle is the top-level output of the L3 LLM planner.
// It is the primary input to the cases stage in --mode llm runs.
type EvidenceBundle struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	Repo          RepoRef        `json:"repo"`
	PlannerMeta   PlannerMeta    `json:"planner_meta"`
	Candidates    []Candidate    `json:"candidates"`
	SinksObserved []SinkHitGroup `json:"sinks_observed,omitempty"`
	ProposedSinks []ProposedSink `json:"proposed_sinks,omitempty"`
	Errors        []RoundError   `json:"errors,omitempty"`
	FinalSummary  string         `json:"final_summary,omitempty"`
}

type PlannerMeta struct {
	RoundsUsed        int    `json:"rounds_used"`
	RoundsBudget      int    `json:"rounds_budget"`
	TokensUsed        int    `json:"tokens_used"`
	WallClockMs       int64  `json:"wall_clock_ms"`
	TerminationReason string `json:"termination_reason"`
	Truncated         bool   `json:"truncated"`
}

type Candidate struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Priority     string   `json:"priority"`
	Paths        []string `json:"paths"`
	Symbols      []string `json:"symbols,omitempty"`
	WhySelected  []string `json:"why_selected"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	SinkCategory string   `json:"sink_category,omitempty"`
	Confidence   float64  `json:"confidence"`
}

type SinkHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

type SinkHitGroup struct {
	Category string    `json:"category"`
	Hits     []SinkHit `json:"hits"`
}

type ProposedSink struct {
	CategoryIDSuggested string   `json:"category_id_suggested"`
	Rationale           string   `json:"rationale"`
	ExampleSymbols      []string `json:"example_symbols,omitempty"`
}

type RoundError struct {
	Round  int    `json:"round"`
	Action string `json:"action"`
	Error  string `json:"error"`
}

// RoundRecord is written to 04_planner/rounds.jsonl (one per line).
// Not fed back to the LLM; for debugging and post-hoc analysis only.
type RoundRecord struct {
	Round        int                `json:"round"`
	Thought      string             `json:"thought,omitempty"`
	Actions      []RoundAction      `json:"actions"`
	Observations []RoundObservation `json:"observations"`
	TokensIn     int                `json:"tokens_in"`
	TokensOut    int                `json:"tokens_out"`
	WallClockMs  int64              `json:"wall_clock_ms"`
}

type RoundAction struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type RoundObservation struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Ref names this one observation: obs:<sample>:<round>:<index>:<hash>.
	// It is what a downstream claim cites when it says where it looked. A
	// reason that cites nothing is free text shaped like a citation, and an
	// audit lead built on one is the same unevidenced anchor with extra steps.
	Ref string `json:"ref,omitempty"`
	// OutputBlob resolves to the UNTRUNCATED body in the blob store. Output
	// below is an excerpt; when the two differ, Truncated says so and this is
	// where the rest lives.
	OutputBlob string `json:"output_blob,omitempty"`
	// ActionIndex is the position within the round's action list. Round alone
	// does not identify an observation — a round runs up to MaxActionsPerRound
	// of them.
	ActionIndex int `json:"action_index"`
	// Phase is the planner phase this observation was made in. Narrative
	// only; it is deliberately absent from Ref, because two --samples passes
	// both walk both phases and a ref built from the phase would collide.
	Phase      string `json:"phase,omitempty"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}
