package artifacts

import "fmt"

const (
	SchemaVersionRepoFactsV1  = "teecheck.repo_facts.v1"
	SchemaVersionProjectMapV1 = "teecheck.project_map.v1"
)

// Capability states, reported per capability rather than as one verdict.
//
// A single global "complete" invites over-trust. Under --build-mode=none the
// symbol table is solid, the call graph is missing every indirect edge, and
// build reachability was never computed at all; a consumer that sees one
// word cannot tell which of those it is holding, and every negative result
// it derives inherits that ambiguity.
const (
	CapabilityAvailable   = "available"
	CapabilityPartial     = "partial"
	CapabilityUnavailable = "unavailable"
)

// Scope strings a capsule's lists carry, so "no callers" is never read as
// "never called" and an absent write is never read as "never written".
const (
	ScopeDirectResolvedCallsOnly = "direct_resolved_calls_only"
	ScopeDirectAssignmentOnly    = "direct_assignment_only"
)

// Call resolution kinds. Direct is the only one that produces a CallEdge;
// the rest are why an UnresolvedCall exists.
const (
	ResolutionDirect   = "direct"
	ResolutionIndirect = "indirect"
	ResolutionUnknown  = "unknown"
)

// SymbolID is a stable identity for one definition.
//
// (file, symbol) is not enough for C/C++: two files can each define a static
// function of the same name, and one translation unit can hold overloads.
// The planner searches by name, receives candidates, and then asks for a
// specific id — so ambiguity is surfaced to the model rather than resolved
// arbitrarily by whichever definition a map wrote last.
type SymbolID string

// MakeSymbolID builds the id. Signature separates overloads; file and line
// separate same-named statics. Nothing here is required to be reversible,
// only stable for a given definition at a given revision.
func MakeSymbolID(lang, file string, line int, name, signature string) SymbolID {
	return SymbolID(fmt.Sprintf("%s:%s:%d:%s%s", lang, file, line, name, signature))
}

// Symbol is one definition the extractor found.
type Symbol struct {
	SymbolID      SymbolID `json:"symbol_id"`
	Name          string   `json:"name"`
	QualifiedName string   `json:"qualified_name,omitempty"`
	File          string   `json:"file"`
	StartLine     int      `json:"start_line"`
	Signature     string   `json:"signature,omitempty"`
	Module        string   `json:"module,omitempty"`
}

// CallEdge is one resolved call, by id at both ends.
//
// The edges are kept whole rather than only as the per-capsule caller and
// callee name lists, because deriving module dependencies from names would
// mean resolving a callee name back to a definition — the guess SymbolID
// exists to prevent.
type CallEdge struct {
	CallerID   SymbolID `json:"caller_id"`
	CalleeID   SymbolID `json:"callee_id"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Resolution string   `json:"resolution"`
}

// UnresolvedCall is one call site whose target the extractor could not name.
//
// A total count is not enough. "Could anything unresolved reach
// shdr_load_pub_key?" cannot be answered from a number, so a missing caller
// stays weak evidence however small the count is. The enclosing symbol and
// the call expression are what make the question answerable at all.
type UnresolvedCall struct {
	EnclosingSymbolID SymbolID `json:"enclosing_symbol_id,omitempty"`
	File              string   `json:"file"`
	Line              int      `json:"line"`
	Expression        string   `json:"expression,omitempty"`
	ResolutionKind    string   `json:"resolution_kind"`
}

// FunctionCapsule is one function's neutral behaviour record.
//
// It carries no priority, no risk label and no TWE mapping, by construction
// and by test. The producer/consumer mismatch that matters is visible from
// the facts alone: on CVE-2026-44362 the capsule for shdr_load_pub_key lists
// no direct write to shdr_pub_key.version while ree_fs_ta_open reads it.
// Naming that "rollback candidate" here would move the judgement back into
// 01, which is the defect this contract exists to prevent.
type FunctionCapsule struct {
	SymbolID SymbolID `json:"symbol_id"`
	Name     string   `json:"name"`
	Module   string   `json:"module"`
	File     string   `json:"file"`
	Line     int      `json:"line"`

	CalledBy []SymbolID `json:"called_by,omitempty"`
	Calls    []SymbolID `json:"calls,omitempty"`

	// FieldAccesses is every "Type.field" the function touches, read or
	// written: CodeQL's FieldAccess matches an assignment's left-hand side,
	// so this cannot be called "reads".
	FieldAccesses []string `json:"field_accesses,omitempty"`
	// DirectFieldWrites is the subset provable as a direct assignment. A
	// field filled by memcpy, through a pointer alias, or by a designated
	// initializer is absent here, and its absence proves nothing.
	DirectFieldWrites []string `json:"direct_field_writes,omitempty"`
}

func (FunctionCapsule) CallersScope() string     { return ScopeDirectResolvedCallsOnly }
func (FunctionCapsule) FieldWritesScope() string { return ScopeDirectAssignmentOnly }

// IndexCapabilities reports what the index can and cannot answer.
type IndexCapabilities struct {
	Symbols           string `json:"symbols"`
	DirectCalls       string `json:"direct_calls"`
	FieldAccesses     string `json:"field_accesses"`
	BuildReachability string `json:"build_reachability"`
	EntrySurfaces     string `json:"entry_surfaces,omitempty"`
}

// EntrySurface is a neutral navigation candidate, not a claim that a function
// is externally reachable or receives untrusted input. Signals describe only
// the structural facts the index observed in its extraction scope.
type EntrySurface struct {
	SymbolID     SymbolID               `json:"symbol_id"`
	Name         string                 `json:"name"`
	Path         string                 `json:"path"`
	Module       string                 `json:"module"`
	StartLine    int                    `json:"start_line"`
	EndLine      int                    `json:"end_line"`
	Signals      []string               `json:"signals"`
	EvidenceRefs []EntrySurfaceEvidence `json:"evidence_refs"`
}

type EntrySurfaceEvidence struct {
	Signal    string `json:"signal"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Detail    string `json:"detail,omitempty"`
}

const (
	EntrySignalExternalLinkage                  = "external_linkage"
	EntrySignalGlobalFunctionPointerInitializer = "global_function_pointer_initializer"
	EntrySignalBufferLengthParameters           = "buffer_length_parameters"
	EntrySignalNoResolvedInternalCallers        = "no_resolved_internal_callers"
)

// RepoFacts is the deterministic whole-repo program index. It answers "what
// structure was observed", never "what is dangerous".
type RepoFacts struct {
	CoverageStatus string            `json:"coverage_status,omitempty"`
	SchemaVersion  string            `json:"schema_version"`
	RunID          string            `json:"run_id"`
	Scope          ScannedScope      `json:"scope"`
	Capabilities   IndexCapabilities `json:"capabilities"`
	// IndexNote names the cause when a capability is degraded, so a reader
	// can tell a repository with no indirect calls from an extractor that
	// could not run.
	IndexNote string `json:"index_note,omitempty"`

	Languages    []string `json:"languages,omitempty"`
	BuildTargets []string `json:"build_targets,omitempty"`

	Symbols   []Symbol          `json:"symbols,omitempty"`
	Capsules  []FunctionCapsule `json:"capsules,omitempty"`
	CallEdges []CallEdge        `json:"call_edges,omitempty"`

	// Call-site accounting. These are counts, and they are deliberately not
	// the lengths of the lists above: a CodeQL result is a set, so two calls
	// on one line with the same expression collapse into one row. On
	// OP-TEE@a9386bf the unresolved list holds 1,423 rows for 1,552
	// unresolved call sites. The lists are deduplicated views; only these
	// numbers can be checked against each other.
	//
	// Two identities hold:
	//
	//	TotalCallSites = ResolvedCallSites + UnresolvedCallSiteCount
	//	ResolvedCallSites = (calls with one in-tree definition)
	//	                    + ExternalCallSites + AmbiguousCallSites
	TotalCallSites          int `json:"total_call_sites"`
	ResolvedCallSites       int `json:"resolved_call_sites"`
	UnresolvedCallSiteCount int `json:"unresolved_call_site_count"`
	// ExternalCallSites call a function with no definition in this tree —
	// memcpy and friends. AmbiguousCallSites call a function defined several
	// times, where which definition the linker picks is not decidable from
	// the source. Neither produces a CallEdge, and both are why a function
	// can show no callers while being called: a consumer reading only the
	// edge list has no way to know that, and these are the scope it needs.
	ExternalCallSites  int `json:"external_call_sites"`
	AmbiguousCallSites int `json:"ambiguous_call_sites"`

	// UnresolvedCallSites is the deduplicated list. See
	// UnresolvedCallSiteCount for the multiplicity.
	UnresolvedCallSites []UnresolvedCall `json:"unresolved_call_sites,omitempty"`
	EntrySurfaces       []EntrySurface   `json:"entry_surfaces,omitempty"`
	EntrySurfaceNote    string           `json:"entry_surface_note,omitempty"`
}

const (
	SchemaVersionBoundaryTopologyV1 = "teecheck.boundary_topology.v1"

	SurfaceBucketDispatchTables       = "dispatch_tables"
	SurfaceBucketRootBoundaries       = "root_boundaries"
	SurfaceBucketStructBridges        = "struct_bridges"
	SurfaceBucketSharedStateLifecycle = "shared_state_lifecycles"
)

// ProjectMap is the navigation view the planner browses.
//
// It never holds the capsules themselves: the full set is 6.36 MB on
// OP-TEE's 11,301 indexed definitions, which no prompt can carry. Pages are
// written to disk and fetched one at a time.
type ProjectMap struct {
	CoverageStatus string            `json:"coverage_status,omitempty"`
	SchemaVersion  string            `json:"schema_version"`
	RunID          string            `json:"run_id"`
	Scope          ScannedScope      `json:"scope"`
	Capabilities   IndexCapabilities `json:"capabilities"`

	Repository        RepositoryCard        `json:"repository"`
	Modules           []ModuleCard          `json:"modules,omitempty"`
	FunctionPages     []FunctionCardPageRef `json:"function_pages,omitempty"`
	EntrySurfaces     []EntrySurface        `json:"entry_surfaces,omitempty"`
	EntrySurfaceNote  string                `json:"entry_surface_note,omitempty"`
	SurfacePartitions []SurfacePartition    `json:"surface_partitions,omitempty"`
	TopologyPath      string                `json:"topology_path,omitempty"`
}

// SurfacePartition summarizes one neutral structural bucket derived from
// resolved call closures and struct-field producer/consumer links.
type SurfacePartition struct {
	Bucket        string     `json:"bucket"`
	Description   string     `json:"description"`
	ClosureCount  int        `json:"closure_count"`
	ModuleCount   int        `json:"module_count"`
	RootSymbolIDs []SymbolID `json:"root_symbol_ids,omitempty"`
}

// ClosureMember is one function reachable within N resolved call hops of an
// entry-surface definition.
type ClosureMember struct {
	SymbolID              SymbolID `json:"symbol_id"`
	Name                  string   `json:"name"`
	Path                  string   `json:"path"`
	Module                string   `json:"module,omitempty"`
	Line                  int      `json:"line"`
	Hop                   int      `json:"hop"`
	DirectFieldWrites     []string `json:"direct_field_writes,omitempty"`
	NonWriteFieldAccesses []string `json:"non_write_field_accesses,omitempty"`
	FieldAccesses         []string `json:"field_accesses,omitempty"`
}

// EntryClosure records the bounded resolved call closure (depth 0..3) of one
// entry-surface candidate so static protocol-unpacking helpers (such as
// set_rmem_param under tee_entry_std) remain attached to their root surface.
type EntryClosure struct {
	RootSymbolID          SymbolID        `json:"root_symbol_id"`
	RootName              string          `json:"root_name"`
	RootPath              string          `json:"root_path"`
	RootModule            string          `json:"root_module,omitempty"`
	RootStartLine         int             `json:"root_start_line"`
	RootEndLine           int             `json:"root_end_line"`
	Signals               []string        `json:"signals"`
	Buckets               []string        `json:"buckets,omitempty"`
	MaxDepth              int             `json:"max_depth"`
	MembersTruncated      bool            `json:"members_truncated,omitempty"`
	Members               []ClosureMember `json:"members,omitempty"`
	DirectFieldWrites     []string        `json:"direct_field_writes,omitempty"`
	NonWriteFieldAccesses []string        `json:"non_write_field_accesses,omitempty"`
	FieldAccesses         []string        `json:"field_accesses,omitempty"`
}

// StructFieldBridge connects indexed definitions that directly assign a
// "Type.field" with definitions that touch the same field. Because CodeQL's
// FieldAccess AST node includes assignment LHS expressions, Accessors names all
// functions touching the field, DirectWriters names functions with a direct
// assignment, and NonWriteAccessors names functions that touch the field
// without a recorded direct assignment in that function. Neither list is a
// complete read/write alias proof.
type StructFieldBridge struct {
	Field             string     `json:"field"`
	DirectWriters     []SymbolID `json:"direct_writers"`
	NonWriteAccessors []SymbolID `json:"non_write_accessors,omitempty"`
	Accessors         []SymbolID `json:"accessors"`
	CrossModule       bool       `json:"cross_module"`
}

// BoundaryTopology persists the detailed 3-hop entry closures and struct-field
// bridges outside project_map.v1.json so paged navigation stays compact.
type BoundaryTopology struct {
	SchemaVersion      string              `json:"schema_version"`
	RunID              string              `json:"run_id"`
	Scope              ScannedScope        `json:"scope"`
	MaxClosureDepth    int                 `json:"max_closure_depth"`
	SurfacePartitions  []SurfacePartition  `json:"surface_partitions,omitempty"`
	EntryClosures      []EntryClosure      `json:"entry_closures,omitempty"`
	StructFieldBridges []StructFieldBridge `json:"struct_field_bridges,omitempty"`
}

// RepositoryCard is the top-level orientation: what the project says it is,
// how it builds, and how big it is.
type RepositoryCard struct {
	// DocumentedPurpose is quoted from the repository's own README, not
	// summarised. A summary is an inference and would need a state; a quote
	// is a fact about the file.
	DocumentedPurpose string   `json:"documented_purpose,omitempty"`
	Languages         []string `json:"languages,omitempty"`
	BuildTargets      []string `json:"build_targets,omitempty"`
	FileCount         int      `json:"file_count,omitempty"`
}

// ModuleCard summarises one module.
//
// FileCount and FunctionCount are what let a reader tell a project's own
// code from vendored dependencies: on OP-TEE, lib/ holds 898 files named
// libmbedtls and libunw, and the deleted keyword fingerprint never reported
// per-module size, so every consumer treated them as first-party code.
type ModuleCard struct {
	Path            string   `json:"path"`
	FileCount       int      `json:"file_count,omitempty"`
	FunctionCount   int      `json:"function_count,omitempty"`
	Exports         []string `json:"exports,omitempty"`
	CallsModules    []string `json:"calls_modules,omitempty"`
	CalledByModules []string `json:"called_by_modules,omitempty"`
}

// FunctionCardPageRef tells the planner a page exists, how big it is, and
// where to fetch it — without shipping its contents.
type FunctionCardPageRef struct {
	Module string `json:"module"`
	Page   int    `json:"page"`
	Count  int    `json:"count"`
	// Path is the page file, relative to the run directory. Without it the
	// planner would have to re-derive the location, and a page it cannot
	// open is a page that does not exist.
	Path string `json:"path"`
}
