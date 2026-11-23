package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/topology"
)

const boundaryClosureNotice = "Boundary closures group 0..3 resolved call hops and recorded field accesses structurally. Indirect calls, macro expansions, and memcpy/pointer-alias writes are omitted; inspect actual source with read_file."

type listBoundaryClosuresArgs struct {
	Bucket string `json:"bucket,omitempty"`
	Module string `json:"module,omitempty"`
	Page   int    `json:"page"`
}

type ListBoundaryClosuresHandler struct{}

func (ListBoundaryClosuresHandler) Name() string { return "list_boundary_closures" }

func (h ListBoundaryClosuresHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args listBoundaryClosuresArgs
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
		}
	}
	if args.Page < 0 || len(args.Bucket) > 128 || len(args.Module) > 512 {
		return fail(h.Name(), "page must be non-negative and bucket/module filters must be short")
	}
	if args.Bucket != "" {
		switch args.Bucket {
		case artifacts.SurfaceBucketDispatchTables,
			artifacts.SurfaceBucketRootBoundaries,
			artifacts.SurfaceBucketStructBridges,
			artifacts.SurfaceBucketSharedStateLifecycle:
		default:
			return fail(h.Name(), fmt.Sprintf("unknown bucket %q; valid buckets: dispatch_tables, root_boundaries, struct_bridges, shared_state_lifecycles", args.Bucket))
		}
	}

	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}
	var topo artifacts.BoundaryTopology
	if err := runfs.ReadJSON(runfs.BoundaryTopologyPath(req.RunDir), &topo); err != nil {
		return fail(h.Name(), fmt.Sprintf("boundary topology unavailable (%v); use list_entry_surfaces or list_functions", err))
	}

	byRoot := make(map[artifacts.SymbolID]artifacts.EntryClosure, len(topo.EntryClosures))
	for _, c := range topo.EntryClosures {
		byRoot[c.RootSymbolID] = c
	}

	var ordered []artifacts.EntryClosure
	if args.Bucket != "" {
		for _, part := range topo.SurfacePartitions {
			if part.Bucket != args.Bucket {
				continue
			}
			for _, id := range part.RootSymbolIDs {
				if c, ok := byRoot[id]; ok {
					ordered = append(ordered, c)
				}
			}
		}
	} else {
		ordered = topology.DiversifyClosures(topo.EntryClosures, topology.MaxPerFileStreak)
	}

	var matched []artifacts.EntryClosure
	for _, c := range ordered {
		if args.Module != "" && c.RootModule != args.Module {
			continue
		}
		matched = append(matched, c)
	}

	// The project map normally stores only partition counts. Do not repeat
	// full root-ID lists if a caller supplied a detailed map instead.
	partitions := append([]artifacts.SurfacePartition(nil), b.m.SurfacePartitions...)
	for i := range partitions {
		partitions[i].RootSymbolIDs = nil
	}
	type closurePage struct {
		Notice            string                       `json:"notice"`
		Capabilities      artifacts.IndexCapabilities  `json:"capabilities"`
		SurfacePartitions []artifacts.SurfacePartition `json:"surface_partitions,omitempty"`
		MatchedCount      int                          `json:"matched_count"`
		Page              int                          `json:"page"`
		TotalPages        int                          `json:"total_pages"`
		Closures          []closureDisplay             `json:"closures"`
		Truncated         bool                         `json:"truncated"`
		NextCursor        *listBoundaryClosuresArgs    `json:"next_cursor,omitempty"`
	}
	marshalPage := func(items []closureDisplay, page, totalPages int) ([]byte, error) {
		var next *listBoundaryClosuresArgs
		if page+1 < totalPages {
			c := args
			c.Page = page + 1
			next = &c
		}
		return json.Marshal(closurePage{
			Notice:       boundaryClosureNotice + " Oversized entries contain a display_summary with original stored-list counts; omitted details are not negative evidence. Inspect listed definitions with get_function_card/read_file.",
			Capabilities: b.m.Capabilities, SurfacePartitions: partitions,
			MatchedCount: len(matched), Page: page, TotalPages: totalPages,
			Closures: items, Truncated: closuresSummarized(items), NextCursor: next,
		})
	}
	items := make([]closureDisplay, 0, len(matched))
	for _, item := range matched {
		items = append(items, closureDisplay{EntryClosure: item})
	}
	pages, err := boundedTopologyPages(items, 8, marshalPage, summarizeClosure)
	if err != nil {
		return fail(h.Name(), err.Error())
	}
	if args.Page >= len(pages) {
		return fail(h.Name(), fmt.Sprintf("closure filter has pages 0..%d, not %d", len(pages)-1, args.Page))
	}
	data, err := marshalPage(pages[args.Page], args.Page, len(pages))
	if err != nil {
		return fail(h.Name(), err.Error())
	}
	return topologyJSONResult(h.Name(), data, closuresSummarized(pages[args.Page]))
}

type getStructFlowsArgs struct {
	TypeOrField     string `json:"type_or_field"`
	SymbolID        string `json:"symbol_id,omitempty"`
	CrossModuleOnly bool   `json:"cross_module_only,omitempty"`
	Page            int    `json:"page"`
}

type GetStructFlowsHandler struct{}

func (GetStructFlowsHandler) Name() string { return "get_struct_flows" }

func (h GetStructFlowsHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args getStructFlowsArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail(h.Name(), fmt.Sprintf("invalid args: %v", err))
	}
	query := strings.TrimSpace(args.TypeOrField)
	if query == "" || len(query) > 256 || len(args.SymbolID) > 2048 || args.Page < 0 {
		return fail(h.Name(), "type_or_field must be a non-empty struct or Type.field query and page must be non-negative")
	}
	b, refusal := openIndex(h.Name(), req.RunDir)
	if refusal != nil {
		return *refusal
	}
	symbol := artifacts.SymbolID(strings.TrimSpace(args.SymbolID))
	if symbol != "" {
		if _, ok := b.byID[symbol]; !ok {
			return fail(h.Name(), "symbol_id is not a definition in this run's program index")
		}
	}
	var topo artifacts.BoundaryTopology
	if err := runfs.ReadJSON(runfs.BoundaryTopologyPath(req.RunDir), &topo); err != nil {
		return fail(h.Name(), fmt.Sprintf("boundary topology unavailable (%v)", err))
	}

	needle := strings.ToLower(query)
	var matched []artifacts.StructFieldBridge
	for _, br := range topo.StructFieldBridges {
		if args.CrossModuleOnly && !br.CrossModule {
			continue
		}
		if symbol != "" && !topologyContainsSymbol(br.Accessors, symbol) && !topologyContainsSymbol(br.DirectWriters, symbol) {
			continue
		}
		lower := strings.ToLower(br.Field)
		if lower == needle || strings.HasPrefix(lower, needle+".") || strings.HasSuffix(lower, "."+needle) || strings.Contains(lower, needle) {
			matched = append(matched, br)
		}
	}

	type bridgePage struct {
		ScopeNote    string              `json:"scope_note"`
		Query        string              `json:"query"`
		SymbolID     artifacts.SymbolID  `json:"symbol_id,omitempty"`
		MatchedCount int                 `json:"matched_count"`
		Page         int                 `json:"page"`
		TotalPages   int                 `json:"total_pages"`
		Bridges      []bridgeDisplay     `json:"bridges"`
		Truncated    bool                `json:"truncated"`
		NextCursor   *getStructFlowsArgs `json:"next_cursor,omitempty"`
	}
	marshalPage := func(items []bridgeDisplay, page, totalPages int) ([]byte, error) {
		var next *getStructFlowsArgs
		if page+1 < totalPages {
			c := args
			c.Page = page + 1
			next = &c
		}
		return json.Marshal(bridgePage{
			ScopeNote: "DirectWriters covers explicit AST field assignments only (omitting memcpy/alias/designated initializers). Accessors includes assignment LHS; NonWriteAccessors means no recorded direct assignment in that function. Oversized lists have a display_summary with original counts; omission proves nothing about safety or accesses. Use symbol_id to retain a specific indexed definition in a summarized list.",
			Query:     query, SymbolID: symbol, MatchedCount: len(matched), Page: page, TotalPages: totalPages,
			Bridges: items, Truncated: bridgesSummarized(items), NextCursor: next,
		})
	}
	items := make([]bridgeDisplay, 0, len(matched))
	for _, item := range matched {
		items = append(items, bridgeDisplay{StructFieldBridge: item})
	}
	compact := func(item bridgeDisplay, limit int) bridgeDisplay { return summarizeBridge(item, limit, symbol) }
	pages, err := boundedTopologyPages(items, 15, marshalPage, compact)
	if err != nil {
		return fail(h.Name(), err.Error())
	}
	if args.Page >= len(pages) {
		return fail(h.Name(), fmt.Sprintf("struct flow query has pages 0..%d, not %d", len(pages)-1, args.Page))
	}
	data, err := marshalPage(pages[args.Page], args.Page, len(pages))
	if err != nil {
		return fail(h.Name(), err.Error())
	}
	return topologyJSONResult(h.Name(), data, bridgesSummarized(pages[args.Page]))
}

// Display summaries never replace the on-disk topology. Counts describe the
// original recorded lists, not a complete semantic flow or read/write proof.
type closureDisplay struct {
	artifacts.EntryClosure
	DisplaySummary *closureDisplaySummary `json:"display_summary,omitempty"`
}

type closureDisplaySummary struct {
	StoredMembers         int `json:"stored_member_count"`
	DirectFieldWrites     int `json:"direct_field_write_count"`
	NonWriteFieldAccesses int `json:"non_write_field_access_count"`
	FieldAccesses         int `json:"field_access_count"`
}

type bridgeDisplay struct {
	artifacts.StructFieldBridge
	DisplaySummary *bridgeDisplaySummary `json:"display_summary,omitempty"`
}

type bridgeDisplaySummary struct {
	DirectWriters     int `json:"direct_writer_count"`
	NonWriteAccessors int `json:"non_write_accessor_count"`
	Accessors         int `json:"accessor_count"`
}

func closuresSummarized(items []closureDisplay) bool {
	for _, item := range items {
		if item.DisplaySummary != nil || item.MembersTruncated {
			return true
		}
	}
	return false
}

func bridgesSummarized(items []bridgeDisplay) bool {
	for _, item := range items {
		if item.DisplaySummary != nil {
			return true
		}
	}
	return false
}

func summarizeClosure(original closureDisplay, limit int) closureDisplay {
	item := original
	item.DisplaySummary = &closureDisplaySummary{
		StoredMembers: len(original.Members), DirectFieldWrites: len(original.DirectFieldWrites),
		NonWriteFieldAccesses: len(original.NonWriteFieldAccesses), FieldAccesses: len(original.FieldAccesses),
	}
	item.DirectFieldWrites = topologyPrefix(original.DirectFieldWrites, limit)
	item.NonWriteFieldAccesses = topologyPrefix(original.NonWriteFieldAccesses, limit)
	item.FieldAccesses = topologyPrefix(original.FieldAccesses, limit)
	// Copy member structs before shortening their lists: summaries must not
	// mutate either the full topology or a previously planned page.
	item.Members = append([]artifacts.ClosureMember(nil), topologyPrefix(original.Members, limit)...)
	item.MembersTruncated = original.MembersTruncated || len(item.Members) < len(original.Members)
	for i := range item.Members {
		item.Members[i].DirectFieldWrites = topologyPrefix(item.Members[i].DirectFieldWrites, limit)
		item.Members[i].NonWriteFieldAccesses = topologyPrefix(item.Members[i].NonWriteFieldAccesses, limit)
		item.Members[i].FieldAccesses = topologyPrefix(item.Members[i].FieldAccesses, limit)
	}
	return item
}

func summarizeBridge(original bridgeDisplay, limit int, symbol artifacts.SymbolID) bridgeDisplay {
	item := original
	item.DisplaySummary = &bridgeDisplaySummary{
		DirectWriters: len(original.DirectWriters), NonWriteAccessors: len(original.NonWriteAccessors), Accessors: len(original.Accessors),
	}
	item.DirectWriters = topologySymbolPrefix(original.DirectWriters, limit, symbol)
	item.NonWriteAccessors = topologySymbolPrefix(original.NonWriteAccessors, limit, symbol)
	item.Accessors = topologySymbolPrefix(original.Accessors, limit, symbol)
	return item
}

func topologyPrefix[T any](items []T, limit int) []T {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func topologyContainsSymbol(items []artifacts.SymbolID, symbol artifacts.SymbolID) bool {
	for _, item := range items {
		if item == symbol {
			return true
		}
	}
	return false
}

func topologySymbolPrefix(items []artifacts.SymbolID, limit int, symbol artifacts.SymbolID) []artifacts.SymbolID {
	if symbol == "" || !topologyContainsSymbol(items, symbol) {
		return topologyPrefix(items, limit)
	}
	// A supplied filter must remain visible even when it falls beyond the
	// ordinary display prefix. Never invent membership in another role list.
	if limit == 0 {
		return []artifacts.SymbolID{symbol}
	}
	prefix := topologyPrefix(items, limit)
	if topologyContainsSymbol(prefix, symbol) {
		return prefix
	}
	out := append([]artifacts.SymbolID(nil), prefix...)
	out[len(out)-1] = symbol
	return out
}

// Probe with the entire response envelope, including a worst-case cursor and
// page-number width. Every item occupies one reachable page. Only an item that
// cannot fit by itself is summarized, with counts and explicit truncation.
func boundedTopologyPages[T any](items []T, maxItems int, marshalPage func([]T, int, int) ([]byte, error), summarize func(T, int) T) ([][]T, error) {
	if len(items) == 0 {
		return [][]T{make([]T, 0)}, nil
	}
	probePage, probeTotal := len(items), len(items)+2
	var pages [][]T
	var current []T
	for _, original := range items {
		item := original
		raw, err := marshalPage([]T{item}, probePage, probeTotal)
		if err != nil {
			return nil, err
		}
		if len(raw) > observationlimits.MaxBytes {
			for _, limit := range []int{8, 4, 1, 0} {
				item = summarize(original, limit)
				raw, err = marshalPage([]T{item}, probePage, probeTotal)
				if err != nil {
					return nil, err
				}
				if len(raw) <= observationlimits.MaxBytes {
					break
				}
			}
			if len(raw) > observationlimits.MaxBytes {
				return nil, fmt.Errorf("a topology entry's identity exceeds the observation limit even without detail lists; inspect its definition directly")
			}
		}
		trial := append(current, item)
		raw, err = marshalPage(trial, probePage, probeTotal)
		if err != nil {
			return nil, err
		}
		if len(current) > 0 && (len(trial) > maxItems || len(raw) > observationlimits.MaxBytes) {
			pages = append(pages, current)
			current = []T{item}
		} else {
			current = trial
		}
	}
	if len(current) > 0 {
		pages = append(pages, current)
	}
	return pages, nil
}

func topologyJSONResult(name string, data []byte, truncated bool) ActionResult {
	if len(data) > observationlimits.MaxBytes || !json.Valid(data) {
		return fail(name, "topology response cannot fit as complete JSON within the observation limit")
	}
	return ActionResult{Name: name, OK: true, Output: string(data), Truncated: truncated}
}

var (
	_ Handler = ListBoundaryClosuresHandler{}
	_ Handler = GetStructFlowsHandler{}
)
