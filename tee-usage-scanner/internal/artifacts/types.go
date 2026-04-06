package artifacts

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
	SupportingFacts    []string        `json:"supporting_facts,omitempty"`
	KnowledgeHints     []KnowledgeHint `json:"knowledge_hints,omitempty"`
	Confidence         string          `json:"confidence"`
	NeedsVerification  bool            `json:"needs_verification"`
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
	SchemaVersion  string   `json:"schema_version"`
	CaseID         string   `json:"case_id"`
	AgentID        string   `json:"agent_id"`
	Status         string   `json:"status"`
	ChecksRun      []string `json:"checks_run,omitempty"`
	ConfirmedFacts []string `json:"confirmed_facts,omitempty"`
	Contradictions []string `json:"contradictions,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}
