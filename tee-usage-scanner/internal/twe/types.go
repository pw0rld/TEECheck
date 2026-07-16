// Package twe defines the TEE Weakness Entry (TWE) catalog and the TrustIR
// data contracts that drive the deterministic TWE pipeline.
//
// A TWE is an executable weakness specification, not a prompt template and
// not an LLM verdict. It fixes a contract between the LLM (which only fills
// TrustIR roles), the Binder, the static fact engine, and the Solver. This
// package covers milestone M1: the loader, schema validation, and the
// TrustIR structs. It has no external process dependencies — no CodeQL, no
// Rust toolchain — so it is the first landable increment of the refactor.
package twe

// Family is one of the supported TWE families. Every entry belongs to exactly
// one, and the value is validated at load time.
type Family string

const (
	FamilyFlow    Family = "Flow"
	FamilyGuard   Family = "Guard"
	FamilyBinding Family = "Binding"
	FamilyState   Family = "State"
	FamilyConfig  Family = "Config"
	FamilyDesign  Family = "Design"
	FamilyLeakage Family = "Leakage"
)

// ValidFamilies is the closed set of families. It matches the twe_family
// vocabulary the benchmark oracles use so the catalog and the corpus stay
// aligned — all seven families, even those without a catalog entry yet, so a
// generator or oracle may reference any of them.
var ValidFamilies = map[Family]bool{
	FamilyFlow:    true,
	FamilyGuard:   true,
	FamilyBinding: true,
	FamilyState:   true,
	FamilyConfig:  true,
	FamilyDesign:  true,
	FamilyLeakage: true,
}

// Entry is one TEE Weakness Entry: the unit of security knowledge the system
// can execute. Every field drives a specific pipeline stage — see the field
// comments. The YAML shape is the authoring format under knowledge/twe/.
type Entry struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	Family  Family `yaml:"family" json:"family"`
	Summary string `yaml:"summary" json:"summary"`

	// ApplicableContexts scopes where the planner should attempt this TWE.
	ApplicableContexts []string `yaml:"applicable_contexts" json:"applicable_contexts"`
	// RequiredTrustIR names the roles the expert LLM must locate in code.
	RequiredTrustIR []string `yaml:"required_trustir" json:"required_trustir"`
	// AllowedEnums constrains the value each role may take. Every key must be
	// a role listed in RequiredTrustIR.
	AllowedEnums map[string][]string `yaml:"allowed_enums" json:"allowed_enums"`
	// CodeQLModules are the prewritten query modules that check the
	// obligation. Consumed by the query generator in M4.
	CodeQLModules []string `yaml:"codeql_modules" json:"codeql_modules"`
	// ViolationCondition is the human-readable obligation the Solver encodes.
	ViolationCondition string `yaml:"violation_condition" json:"violation_condition"`
	// AcceptedSuppressors are the relations that let the Solver downgrade or
	// dismiss a candidate.
	AcceptedSuppressors []string `yaml:"accepted_suppressors" json:"accepted_suppressors"`
	// Fixtures links this TWE to benchmark cases that prove it works. The
	// values are benchmark case IDs (e.g. TWE-BIND-0001).
	Fixtures []string `yaml:"fixtures" json:"fixtures"`
}

// Loc is a source location the expert LLM points at when filling a role.
type Loc struct {
	Path   string `yaml:"path" json:"path"`
	Line   int    `yaml:"line" json:"line"`
	Symbol string `yaml:"symbol" json:"symbol"`
}

// RoleCandidate is one filled role in a TrustIRCandidate: which enum value
// the role takes and where in the code it lives.
type RoleCandidate struct {
	Enum string `json:"enum"`
	Loc  Loc    `json:"loc"`
}

// TrustIRCandidate is the LLM's output for one site: it says which source
// locations play the roles a TWE requires. It is the last LLM-authored
// artifact in the pipeline — everything after it is deterministic.
type TrustIRCandidate struct {
	TWEID  string                   `json:"twe_id"`
	SiteID string                   `json:"site_id"`
	Roles  map[string]RoleCandidate `json:"roles"`
}

// RoleResolved is a role bound to a stable code-graph node by the Binder.
type RoleResolved struct {
	Enum   string `json:"enum"`
	NodeID string `json:"node_id"`
}

// TrustIRResolved is the Binder's output: candidate roles resolved to stable
// code node IDs, plus any roles it could not bind.
type TrustIRResolved struct {
	TWEID         string                  `json:"twe_id"`
	SiteID        string                  `json:"site_id"`
	Roles         map[string]RoleResolved `json:"roles"`
	RejectedRoles []string                `json:"rejected_roles"`
}
