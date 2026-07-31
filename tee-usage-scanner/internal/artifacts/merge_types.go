package artifacts

import (
	"encoding/json"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// Canonical schema_version values for the §9 contracts, matching the "const"
// declared in each schemas/*.json file. schema_version is never inferred
// from a file's name or path — see internal/schema for the validator that
// checks a decoded artifact's own field against these values.
const (
	SchemaVersionProjectProfileV2       = "teecheck.project_profile.v2"
	SchemaVersionArchitectureV1         = "teecheck.architecture.v1"
	SchemaVersionProjectInvariantV1     = "teecheck.project_invariant.v1"
	SchemaVersionTWEKnowledgeManifestV1 = "teecheck.twe_knowledge_manifest.v1"
	// SchemaVersionToolFactV1 is "teecheck.trustir_result.v1", not
	// "teecheck.tool_fact.v1": ToolFact validates against the "result" half
	// of schemas/trustir-tool.v1.json (see ToolFact's doc comment).
	SchemaVersionToolFactV1         = "teecheck.trustir_result.v1"
	SchemaVersionTWEInvestigationV1 = "teecheck.twe_investigation.v1"
	SchemaVersionFindingV3          = "teecheck.finding.v3"
)

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

// CitedBytes converts this EvidenceReference into the shape
// internal/citations validates against (PR-04's bridge between the two
// contracts — see internal/architecture's package doc for why this is a
// pure, hash-free conversion rather than a stored-hash field on
// EvidenceReference). citations.CitedBytes.Valid/Resolve then decide
// whether it is actually checkable: File == "" (an artifact_ref-only
// reference into a persisted tool result) or StartLine < 1 (evidence
// naming a path but no line, e.g. "this manifest file exists") both
// produce a CitedBytes that Valid() reports false for a byte-range
// check — callers that want to accept path-only evidence must check
// File/StartLine themselves before falling back to a plain file-exists
// check; this method only handles the byte-range case.
//
// A citation with StartLine set but EndLine omitted (EndLine < StartLine,
// including the zero value) is normalized to a single-line range: the JSON
// contract asks for an inclusive start/end pair, but a citation naming one
// line only should not be rejected purely for omitting a redundant
// end_line.
func (e EvidenceReference) CitedBytes() citations.CitedBytes {
	end := e.EndLine
	if end < e.StartLine {
		end = e.StartLine
	}
	return citations.CitedBytes{File: e.File, StartLine: e.StartLine, EndLine: end}
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
// from TWE prior knowledge and the ArchitectureModel. RelatedTWEs and
// VerificationPlan intentionally omit `omitempty`: project-invariant.v1.json
// requires both keys to be present (related_twes additionally requires at
// least one entry) even when the Planner has not yet filled them in, so an
// empty-but-present `[]` is a distinct, valid state from the key being
// absent.
type ProjectInvariant struct {
	SchemaVersion         string   `json:"schema_version"`
	InvariantID           string   `json:"invariant_id"`
	Statement             string   `json:"statement"`
	RelatedTWEs           []string `json:"related_twes"`
	Parties               []string `json:"parties,omitempty"`
	Assets                []string `json:"assets,omitempty"`
	Boundaries            []string `json:"boundaries,omitempty"`
	Entrypoints           []string `json:"entrypoints,omitempty"`
	AuthorityPoints       []string `json:"authority_points,omitempty"`
	RequiredProperties    []string `json:"required_properties,omitempty"`
	ExpectedDefenses      []string `json:"expected_defenses,omitempty"`
	ArchitectureRefs      []string `json:"architecture_refs,omitempty"`
	VerificationPlan      []string `json:"verification_plan"`
	UnresolvedAssumptions []string `json:"unresolved_assumptions,omitempty"`
	Status                string   `json:"status"`
	// Classification mirrors TWEInvestigation.Classification. catalog_gap
	// marks an obligation no existing TWE covers — a first-class signal so
	// downstream keys off this rather than parsing the related_twes sentinel.
	Classification string              `json:"classification,omitempty"`
	Evidence       []EvidenceReference `json:"evidence,omitempty"`
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

	// ContextTokenEstimate records how large the compiled prior-knowledge
	// context actually was. The budget in twecontext fails compilation
	// rather than truncating, so this is the observable that shows how much
	// headroom is left before it fires.
	ContextTokenEstimate int `json:"context_token_estimate,omitempty"`
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
//
// It is validated against schemas/trustir-tool.v1.json's "result" variant
// (schema_version "teecheck.trustir_result.v1"). That schema still models
// today's request/result tool protocol, so it requires RequestID — a pairing
// concept from the live operation model, not from §9.6's fact list
// (tool/version, repo commit, query hash, structured result, locations,
// status, artifact ref). PR-05 replaces the operation model with a fact
// layer per §19/§20; RequestID is the field most likely to become dead at
// that point, since a persisted fact has no paired live request to point
// back to. It stays required here only to satisfy the schema as it exists
// today — see the PR-01 handoff notes for the full field-by-field list.
type ToolFact struct {
	SchemaVersion   string `json:"schema_version"`
	RequestID       string `json:"request_id"`
	FactID          string `json:"fact_id"`
	Tool            string `json:"tool"`
	ToolVersion     string `json:"tool_version,omitempty"`
	Operation       string `json:"operation"`
	RepoCommit      string `json:"repo_commit"`
	ArgumentsSHA256 string `json:"arguments_sha256,omitempty"`
	Status          string `json:"status"`
	// Locations is deliberately NOT omitempty. A successful query that
	// matched nothing used to serialise with no locations key at all,
	// leaving "we looked and found nothing" indistinguishable on disk from
	// "this field was never populated" — and the fixed half of a
	// vulnerable/fixed differential is read entirely on the strength of that
	// first reading. Producers initialise it (see trustirfacts.newFact) so
	// every status emits an array and stays valid against
	// trustir-tool.v1.json, which types locations as an array.
	Locations []ToolLocation   `json:"locations"`
	Paths     [][]ToolPathStep `json:"paths,omitempty"`
	// Findings carries each result's message and the sites it names. See
	// ToolFinding: the query's conclusion is in the message, and keeping
	// only Locations discarded it along with every secondary site.
	Findings     []ToolFinding   `json:"findings,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	ArtifactRef  string          `json:"artifact_ref,omitempty"`
	Error        string          `json:"error,omitempty"`
	CoverageGaps []string        `json:"coverage_gaps,omitempty"`
	Truncated    bool            `json:"truncated,omitempty"`
}

// MarshalJSON renders a nil Locations as [] so that "the query ran and
// matched nothing" is always stated rather than omitted, without every
// producer having to remember to initialise the slice — and without emitting
// null, which trustir-tool.v1.json (locations: {"type": "array"}) rejects.
// Status still says whether the query ran at all; this only removes the
// ambiguity within a success.
func (f ToolFact) MarshalJSON() ([]byte, error) {
	type alias ToolFact
	if f.Locations == nil {
		f.Locations = []ToolLocation{}
	}
	return json.Marshal(alias(f))
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
