package artifacts

import "encoding/json"

// EvidenceState describes how strongly a project-understanding statement is
// grounded. These values are deliberately separate from finding confidence:
// they describe the provenance of an architecture fact, not vulnerability
// likelihood.
type EvidenceState string

const (
	EvidenceObserved   EvidenceState = "observed"
	EvidenceInferred   EvidenceState = "inferred"
	EvidenceDocumented EvidenceState = "documented"
	EvidenceUnknown    EvidenceState = "unknown"
)

// EvidenceReference points to source, documentation, or a persisted tool
// artifact. Source byte hashes are resolved later by the citations package;
// this cross-language contract intentionally stays transport-friendly.
type EvidenceReference struct {
	Kind        string `json:"kind"`
	File        string `json:"file,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	ArtifactRef string `json:"artifact_ref,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Note        string `json:"note,omitempty"`
}

// ProfileSignal is a deterministic fingerprint observation. Candidate role
// signals remain candidates until the Architecture Agent grounds them.
type ProfileSignal struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	Name       string              `json:"name"`
	Status     string              `json:"status,omitempty"`
	Detector   string              `json:"detector,omitempty"`
	Scope      string              `json:"scope,omitempty"`
	Confidence string              `json:"confidence,omitempty"`
	Evidence   []EvidenceReference `json:"evidence,omitempty"`
}

// ProjectProfileV2 is the canonical merged fingerprint contract. It is kept
// alongside the legacy ProjectProfile during migration so historical runs and
// consumers continue to decode unchanged.
type ProjectProfileV2 struct {
	SchemaVersion    string          `json:"schema_version"`
	RunID            string          `json:"run_id"`
	Repo             RepoRef         `json:"repo"`
	Languages        []string        `json:"languages,omitempty"`
	BuildSystems     []string        `json:"build_systems,omitempty"`
	TEEPlatforms     []ProfileSignal `json:"tee_platforms,omitempty"`
	CandidateRoles   []ProfileSignal `json:"candidate_roles,omitempty"`
	TrustArtifacts   []ProfileSignal `json:"trust_artifacts,omitempty"`
	Manifests        []ProfileSignal `json:"manifests,omitempty"`
	BoundarySignals  []ProfileSignal `json:"boundary_signals,omitempty"`
	StateSignals     []ProfileSignal `json:"state_signals,omitempty"`
	SensitivePaths   []string        `json:"sensitive_paths,omitempty"`
	TopLevelDirs     []string        `json:"top_level_dirs,omitempty"`
	FrameworkHints   []string        `json:"framework_hints,omitempty"`
	CoverageWarnings []string        `json:"coverage_warnings,omitempty"`
}

// ArchitectureElement is a party, component, role, asset, trust zone, or
// entrypoint in the structured architecture model.
type ArchitectureElement struct {
	ID           string              `json:"id"`
	Kind         string              `json:"kind"`
	Name         string              `json:"name"`
	Description  string              `json:"description,omitempty"`
	Role         string              `json:"role,omitempty"`
	Zone         string              `json:"zone,omitempty"`
	State        EvidenceState       `json:"state"`
	Confidence   string              `json:"confidence,omitempty"`
	Evidence     []EvidenceReference `json:"evidence,omitempty"`
	Dependencies []string            `json:"dependencies,omitempty"`
}

// ArchitectureRelation captures a trust boundary, data flow, state lifecycle,
// or assumption edge between architecture elements.
type ArchitectureRelation struct {
	ID           string              `json:"id"`
	Kind         string              `json:"kind"`
	From         string              `json:"from"`
	To           string              `json:"to"`
	Description  string              `json:"description,omitempty"`
	State        EvidenceState       `json:"state"`
	Confidence   string              `json:"confidence,omitempty"`
	Evidence     []EvidenceReference `json:"evidence,omitempty"`
	Dependencies []string            `json:"dependencies,omitempty"`
}

// ArchitectureModel is the canonical machine-readable dossier. Markdown is a
// derived presentation and must never become a second source of truth.
type ArchitectureModel struct {
	SchemaVersion         string                 `json:"schema_version"`
	RunID                 string                 `json:"run_id"`
	Repo                  RepoRef                `json:"repo"`
	Parties               []ArchitectureElement  `json:"parties,omitempty"`
	Components            []ArchitectureElement  `json:"components,omitempty"`
	Roles                 []ArchitectureElement  `json:"roles,omitempty"`
	Assets                []ArchitectureElement  `json:"assets,omitempty"`
	TrustZones            []ArchitectureElement  `json:"trust_zones,omitempty"`
	Entrypoints           []ArchitectureElement  `json:"entrypoints,omitempty"`
	Boundaries            []ArchitectureRelation `json:"boundaries,omitempty"`
	DataFlows             []ArchitectureRelation `json:"data_flows,omitempty"`
	StateLifecycles       []ArchitectureRelation `json:"state_lifecycles,omitempty"`
	TrustAssumptions      []ArchitectureElement  `json:"trust_assumptions,omitempty"`
	DeploymentAssumptions []ArchitectureElement  `json:"deployment_assumptions,omitempty"`
	Unknowns              []ArchitectureElement  `json:"unknowns,omitempty"`
}

// ProjectInvariant is a project-specific security obligation instantiated
// from TWE prior knowledge and the ArchitectureModel.
type ProjectInvariant struct {
	SchemaVersion         string              `json:"schema_version"`
	InvariantID           string              `json:"invariant_id"`
	Statement             string              `json:"statement"`
	RelatedTWEs           []string            `json:"related_twes,omitempty"`
	Parties               []string            `json:"parties,omitempty"`
	Assets                []string            `json:"assets,omitempty"`
	Boundaries            []string            `json:"boundaries,omitempty"`
	Entrypoints           []string            `json:"entrypoints,omitempty"`
	AuthorityPoints       []string            `json:"authority_points,omitempty"`
	RequiredProperties    []string            `json:"required_properties,omitempty"`
	ExpectedDefenses      []string            `json:"expected_defenses,omitempty"`
	ArchitectureRefs      []string            `json:"architecture_refs,omitempty"`
	VerificationPlan      []string            `json:"verification_plan,omitempty"`
	UnresolvedAssumptions []string            `json:"unresolved_assumptions,omitempty"`
	Status                string              `json:"status"`
	Evidence              []EvidenceReference `json:"evidence,omitempty"`
}

// ProjectInvariants is the persisted collection produced once per run.
type ProjectInvariants struct {
	SchemaVersion string             `json:"schema_version"`
	RunID         string             `json:"run_id"`
	Invariants    []ProjectInvariant `json:"invariants"`
}

// TWEKnowledgeManifest pins the exact playbook knowledge visible to agents.
type TWEKnowledgeManifest struct {
	SchemaVersion  string   `json:"schema_version"`
	CatalogVersion string   `json:"catalog_version,omitempty"`
	CatalogSHA256  string   `json:"catalog_sha256"`
	ContextSHA256  string   `json:"context_sha256"`
	TWEIDs         []string `json:"twe_ids"`
}

// ToolLocation and ToolPathStep are transport-neutral code facts returned by
// TrustIR, CodeQL, or other structured tools.
type ToolLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line,omitempty"`
	Symbol    string `json:"symbol,omitempty"`
}

type ToolPathStep struct {
	Location ToolLocation `json:"location"`
	Kind     string       `json:"kind,omitempty"`
	Message  string       `json:"message,omitempty"`
}

// ToolFact is immutable after persistence. Agent outputs reference it by ID
// rather than copying or rewriting the underlying static result.
type ToolFact struct {
	SchemaVersion   string           `json:"schema_version"`
	FactID          string           `json:"fact_id"`
	Tool            string           `json:"tool"`
	ToolVersion     string           `json:"tool_version,omitempty"`
	Operation       string           `json:"operation"`
	RepoCommit      string           `json:"repo_commit"`
	ArgumentsSHA256 string           `json:"arguments_sha256,omitempty"`
	Status          string           `json:"status"`
	Locations       []ToolLocation   `json:"locations,omitempty"`
	Paths           [][]ToolPathStep `json:"paths,omitempty"`
	Result          json.RawMessage  `json:"result,omitempty"`
	ArtifactRef     string           `json:"artifact_ref,omitempty"`
	Error           string           `json:"error,omitempty"`
	CoverageGaps    []string         `json:"coverage_gaps,omitempty"`
	Truncated       bool             `json:"truncated,omitempty"`
}

// TWEInvestigation is the Planner's structured, still-reviewable application
// of one or more playbooks to the current project.
type TWEInvestigation struct {
	SchemaVersion    string                  `json:"schema_version"`
	InvestigationID  string                  `json:"investigation_id"`
	TWEIDs           []string                `json:"twe_ids"`
	InvariantIDs     []string                `json:"invariant_ids,omitempty"`
	ArchitectureRefs []string                `json:"architecture_refs,omitempty"`
	Classification   string                  `json:"classification"`
	ObservedFlow     []ToolPathStep          `json:"observed_flow,omitempty"`
	FilledRoles      map[string]ToolLocation `json:"filled_roles,omitempty"`
	MissingRoles     []string                `json:"missing_roles,omitempty"`
	RequiredEvidence []string                `json:"required_evidence,omitempty"`
	CounterEvidence  []string                `json:"counterevidence,omitempty"`
	CoverageGaps     []string                `json:"coverage_gaps,omitempty"`
	ToolFactRefs     []string                `json:"tool_fact_refs,omitempty"`
}

// AgentAssessment is intentionally separate from ToolFact and HumanVerdict.
type AgentAssessment struct {
	Status     string `json:"status"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

type HumanVerdict struct {
	Verdict            string `json:"verdict"`
	ReasonCode         string `json:"reason_code,omitempty"`
	CorrectedSeverity  string `json:"corrected_severity,omitempty"`
	ConfidenceOverride string `json:"confidence_override,omitempty"`
	ReviewedAt         string `json:"reviewed_at,omitempty"`
}

// UnifiedFindingV3 is additive during migration; the current Findings v2
// remains untouched until all consumers have adapters.
type UnifiedFindingV3 struct {
	SchemaVersion        string              `json:"schema_version"`
	FindingID            string              `json:"finding_id"`
	RelatedTWEs          []string            `json:"related_twes,omitempty"`
	RelatedInvariants    []string            `json:"related_invariants,omitempty"`
	ArchitectureRefs     []string            `json:"architecture_refs,omitempty"`
	Classification       string              `json:"classification,omitempty"`
	Summary              string              `json:"summary"`
	ToolFactRefs         []string            `json:"tool_fact_refs,omitempty"`
	AgentAssessment      AgentAssessment     `json:"agent_assessment"`
	AttackPath           []ToolPathStep      `json:"attack_path,omitempty"`
	AnchoredEvidence     []EvidenceReference `json:"anchored_evidence,omitempty"`
	UnanchoredHypotheses []string            `json:"unanchored_hypotheses,omitempty"`
	CoverageGaps         []string            `json:"coverage_gaps,omitempty"`
	HumanVerdict         *HumanVerdict       `json:"human_verdict,omitempty"`
}
