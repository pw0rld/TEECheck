package artifacts

import (
	"encoding/json"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	RepoURL       string            `json:"repo_url"`
	LocalPath     string            `json:"local_path"`
	Commit        string            `json:"commit"`
	Focus         string            `json:"focus"`
	CreatedAt     string            `json:"created_at"`
	ToolVersions  map[string]string `json:"tool_versions,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
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
	FindingID  string   `json:"finding_id"`
	SliceID    string   `json:"slice_id"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Files      []string `json:"files,omitempty"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence,omitempty"`
}

type PromptSnippet struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Content   string `json:"content"`
}

type ProjectProfile struct {
	SchemaVersion  string   `json:"schema_version"`
	RunID          string   `json:"run_id"`
	Repo           RepoRef  `json:"repo"`
	Languages      []string `json:"languages,omitempty"`
	FrameworkHints []string `json:"framework_hints,omitempty"`
	TopLevelDirs   []string `json:"top_level_dirs,omitempty"`
	SensitivePaths []string `json:"sensitive_paths,omitempty"`
	Notes          []string `json:"notes,omitempty"`
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
}

type Hypothesis struct {
	SchemaVersion      string          `json:"schema_version"`
	CaseID             string          `json:"case_id"`
	AgentID            string          `json:"agent_id"`
	Title              string          `json:"title"`
	Summary            string          `json:"summary"`
	SuspectedIssue     string          `json:"suspected_issue"`
	MissingObligations []string        `json:"missing_obligations,omitempty"`
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
	KnowledgeHints []KnowledgeHint    `json:"knowledge_hints,omitempty"`
	Confidence     string             `json:"confidence"`
	NeedsVerification bool            `json:"needs_verification"`
	// Cited is the flat hypothesis-level citation pool. v1.1.1
	// populates it as the union of every citation across CitedFacts
	// (de-duplicated) so the older "Cited" reading path
	// (report rendering, legacy stats) keeps working during the
	// migration. Stats prefers CitedFacts when present; the Cited
	// field is the fallback for legacy hypotheses.
	Cited []citations.CitedBytes `json:"cited,omitempty"`
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
}

type VerificationMemo struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	AgentID       string `json:"agent_id"`
	Status        string `json:"status"`
	ChecksRun     []string `json:"checks_run,omitempty"`
	// ConfirmedFacts holds the validated free-text claims produced
	// by the verifier — the Text of every ConfirmedCitedFacts entry
	// whose citations all resolved against the live repo. Legacy
	// memos used this as the only confirmed-fact field. v1.1.2+
	// should prefer ConfirmedCitedFacts and treat ConfirmedFacts
	// as a display fallback. Same exclusion rule as expert: facts
	// whose citations failed are NOT mirrored here.
	ConfirmedFacts []string `json:"confirmed_facts,omitempty"`
	// ConfirmedCitedFacts is the v1.1.2 canonical confirmed-fact
	// field. Each entry pairs a confirmation claim with the byte
	// regions backing it.
	ConfirmedCitedFacts []citations.CitedFact `json:"confirmed_cited_facts,omitempty"`
	// Contradictions holds the validated contradiction text. Same
	// dual-field semantics as ConfirmedFacts.
	Contradictions []string `json:"contradictions,omitempty"`
	// ContradictedCitedFacts is the v1.1.2 canonical contradiction
	// field with byte citations.
	ContradictedCitedFacts []citations.CitedFact `json:"contradicted_cited_facts,omitempty"`
	Notes                  []string              `json:"notes,omitempty"`
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
}

type ReviewRecord struct {
	SchemaVersion string   `json:"schema_version"`
	CaseID        string   `json:"case_id"`
	FindingID     string   `json:"finding_id"`
	Verdict       string   `json:"verdict"`
	Severity      string   `json:"severity"`
	Tags          []string `json:"tags,omitempty"`
	Notes         string   `json:"notes,omitempty"`
	ReviewerID    string   `json:"reviewer_id,omitempty"`
	ReviewedAt    string   `json:"reviewed_at"`
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
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}
