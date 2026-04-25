// Package sinks loads, validates, and matches against the planner's
// sink catalogs. A sink catalog is a hand-curated list of code
// constructs the LLM uses as anchors for reverse-trace audits.
//
// See knowledge/sinks/README.md for the JSON schema and the audit
// semantics of "sink" in this codebase.
package sinks

const SchemaVersion = "teecheck.sink_catalog.v2"

// Catalog is the top-level loaded form of a per-language JSON file.
type Catalog struct {
	SchemaVersion string  `json:"schema_version"`
	Language      string  `json:"language"`
	Groups        []Group `json:"groups"`
}

// Group bundles related categories under a single LLM-facing
// description. The LLM lists groups first ("*" scope) before drilling
// into a specific group.
type Group struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Categories  []Category `json:"categories"`
}

// Category is a single sink class the LLM can ask reverse_trace to
// anchor on. The Match field describes how the planner identifies
// concrete code sites that belong to this category.
type Category struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Match        Match  `json:"match"`
	SeverityHint string `json:"severity_hint"`
}

// Match describes how to find concrete sites for a Category.
//
// Two kinds:
//   - "symbol": glob-match against fully-qualified symbol names
//     (used by reverse_trace's call-site search). Symbols field is
//     the glob list, Patterns must be empty.
//   - "syntax": literal text match against tree-sitter node text
//     (used for non-callable constructs like derive attributes).
//     Patterns field is the text list, Symbols must be empty.
type Match struct {
	Kind     string   `json:"kind"`
	Symbols  []string `json:"symbols,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
}

const (
	MatchKindSymbol = "symbol"
	MatchKindSyntax = "syntax"
)
