package artifacts

import "encoding/json"

const (
	SchemaVersionCaseInvariantV2       = "teecheck.case_invariant.v2"
	SchemaVersionInvariantAssessmentV1 = "teecheck.invariant_assessment.v1"
)

// ContractSubject identifies a definition; source coordinates and content hash
// are bound against the current revision, never copied to a re-verification.
type ContractSubject struct {
	Path          string   `json:"path"`
	Symbol        string   `json:"symbol"`
	SymbolID      SymbolID `json:"symbol_id,omitempty"`
	StartLine     int      `json:"start_line,omitempty"`
	EndLine       int      `json:"end_line,omitempty"`
	ContentSHA256 string   `json:"content_sha256,omitempty"`
}

type ContractProperty struct {
	Kind         string   `json:"kind"`
	Statement    string   `json:"statement"`
	Source       string   `json:"source,omitempty"`
	Destination  string   `json:"destination,omitempty"`
	Authority    string   `json:"authority,omitempty"`
	TargetFields []string `json:"target_fields,omitempty"`
}

// Kind separates source citations, recorded observations, and ToolFact files.
type ContractEvidenceRef struct {
	Kind          string `json:"kind"`
	Ref           string `json:"ref,omitempty"`
	Path          string `json:"path,omitempty"`
	Symbol        string `json:"symbol,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
}

type ContractQuery struct {
	Backend    string            `json:"backend"`
	Operation  string            `json:"operation"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// CaseInvariantV2 is an obligation, not a verdict. An empty query list means
// there is no registered verification method; it does not invalidate the question.
type CaseInvariantV2 struct {
	SchemaVersion       string                `json:"schema_version"`
	InvariantID         string                `json:"invariant_id"`
	DefinitionHash      string                `json:"definition_hash"`
	Origin              string                `json:"origin"`
	LeadRef             string                `json:"lead_ref,omitempty"`
	Scope               ScannedScope          `json:"scope"`
	Subjects            []ContractSubject     `json:"subjects"`
	Preconditions       []string              `json:"preconditions"`
	RequiredProperty    ContractProperty      `json:"required_property"`
	SecurityEffect      string                `json:"security_effect"`
	EvidenceRefs        []ContractEvidenceRef `json:"evidence_refs"`
	VerificationQueries []ContractQuery       `json:"verification_queries"`
	RelatedTWEs         []string              `json:"related_twes"`
	Grounding           string                `json:"grounding"`
}

// Each assessment and each review concerns exactly one logical contract.
// A local violation need not carry a complete system attack chain.
type InvariantAssessment struct {
	SchemaVersion          string                `json:"schema_version"`
	InvariantID            string                `json:"invariant_id"`
	DefinitionHash         string                `json:"definition_hash"`
	Scope                  ScannedScope          `json:"scope"`
	Assessment             string                `json:"assessment"`
	ReasonCode             string                `json:"reason_code"`
	Reason                 string                `json:"reason"`
	VerificationBasis      string                `json:"verification_basis"`
	QueryOperation         string                `json:"query_operation,omitempty"`
	SourceCorroborated     bool                  `json:"source_corroborated"`
	PreconditionsSatisfied bool                  `json:"preconditions_satisfied"`
	AttackChainComplete    bool                  `json:"attack_chain_complete"`
	EvidenceRefs           []ContractEvidenceRef `json:"evidence_refs"`
	Witness                []ContractSubject     `json:"witness"`
	Contradictions         []string              `json:"contradictions,omitempty"`
	MissingEvidence        []string              `json:"missing_evidence,omitempty"`
}

type ContractReview struct {
	InvariantID            string            `json:"invariant_id"`
	Position               string            `json:"position"`
	Reason                 string            `json:"reason"`
	PreconditionsSatisfied bool              `json:"preconditions_satisfied"`
	AttackChainComplete    bool              `json:"attack_chain_complete"`
	Witness                []ContractSubject `json:"witness"`
	CounterEvidence        []string          `json:"counter_evidence,omitempty"`
}

// Required collections are arrays even when no query or evidence is available.
func (c CaseInvariantV2) MarshalJSON() ([]byte, error) {
	type wire CaseInvariantV2
	if c.Subjects == nil {
		c.Subjects = []ContractSubject{}
	}
	if c.Preconditions == nil {
		c.Preconditions = []string{}
	}
	if c.EvidenceRefs == nil {
		c.EvidenceRefs = []ContractEvidenceRef{}
	}
	if c.VerificationQueries == nil {
		c.VerificationQueries = []ContractQuery{}
	}
	if c.RelatedTWEs == nil {
		c.RelatedTWEs = []string{}
	}
	return json.Marshal(wire(c))
}
func (a InvariantAssessment) MarshalJSON() ([]byte, error) {
	type wire InvariantAssessment
	if a.EvidenceRefs == nil {
		a.EvidenceRefs = []ContractEvidenceRef{}
	}
	if a.Witness == nil {
		a.Witness = []ContractSubject{}
	}
	return json.Marshal(wire(a))
}
