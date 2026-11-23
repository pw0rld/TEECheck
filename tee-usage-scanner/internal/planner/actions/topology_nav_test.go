package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/topology"
)

func TestTopologyNavHandlers_BrowseClosuresAndStructFlows(t *testing.T) {
	runDir := t.TempDir()
	entryID := artifacts.MakeSymbolID("cpp", "core/entry.c", 10, "entry_cmd", "(void*)")
	helperID := artifacts.MakeSymbolID("cpp", "core/entry.c", 30, "unpack_param", "(void*)")
	readerID := artifacts.MakeSymbolID("cpp", "core/mm.c", 50, "consume_param", "(void*)")

	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1,
		RunID:         "nav-test",
		Capabilities: artifacts.IndexCapabilities{
			Symbols:       artifacts.CapabilityAvailable,
			DirectCalls:   artifacts.CapabilityAvailable,
			FieldAccesses: artifacts.CapabilityPartial,
			EntrySurfaces: artifacts.CapabilityAvailable,
		},
		Symbols: []artifacts.Symbol{
			{SymbolID: entryID, Name: "entry_cmd", File: "core/entry.c", StartLine: 10, Module: "core"},
			{SymbolID: helperID, Name: "unpack_param", File: "core/entry.c", StartLine: 30, Module: "core"},
			{SymbolID: readerID, Name: "consume_param", File: "core/mm.c", StartLine: 50, Module: "mm"},
		},
		Capsules: []artifacts.FunctionCapsule{
			{SymbolID: entryID, Name: "entry_cmd", Module: "core", File: "core/entry.c", Line: 10, Calls: []artifacts.SymbolID{helperID}},
			{SymbolID: helperID, Name: "unpack_param", Module: "core", File: "core/entry.c", Line: 30, CalledBy: []artifacts.SymbolID{entryID}, FieldAccesses: []string{"shm_param.size"}, DirectFieldWrites: []string{"shm_param.size"}},
			{SymbolID: readerID, Name: "consume_param", Module: "mm", File: "core/mm.c", Line: 50, FieldAccesses: []string{"shm_param.size"}},
		},
		CallEdges: []artifacts.CallEdge{
			{CallerID: entryID, CalleeID: helperID, File: "core/entry.c", Line: 15, Resolution: artifacts.ResolutionDirect},
		},
	}
	entries := []artifacts.EntrySurface{{
		SymbolID: entryID, Name: "entry_cmd", Path: "core/entry.c", Module: "core", StartLine: 10, EndLine: 20,
		Signals: []string{artifacts.EntrySignalGlobalFunctionPointerInitializer},
	}}
	topo := topology.Build("nav-test", artifacts.ScannedScope{}, facts, entries)
	pm := artifacts.ProjectMap{
		SchemaVersion:     artifacts.SchemaVersionProjectMapV1,
		RunID:             "nav-test",
		Capabilities:      facts.Capabilities,
		EntrySurfaces:     entries,
		SurfacePartitions: topo.SurfacePartitions,
		TopologyPath:      "01_context/boundary_topology.v1.json",
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(runDir), pm); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.BoundaryTopologyPath(runDir), topo); err != nil {
		t.Fatal(err)
	}

	closureRes := ListBoundaryClosuresHandler{}.Run(context.Background(), ActionRequest{
		Name:   "list_boundary_closures",
		RunDir: runDir,
		Args:   json.RawMessage(`{"bucket":"struct_bridges","page":0}`),
	})
	if !closureRes.OK || !strings.Contains(closureRes.Output, "unpack_param") {
		t.Fatalf("list_boundary_closures failed: %+v", closureRes)
	}

	flowRes := GetStructFlowsHandler{}.Run(context.Background(), ActionRequest{
		Name:   "get_struct_flows",
		RunDir: runDir,
		Args:   json.RawMessage(`{"type_or_field":"shm_param","cross_module_only":true}`),
	})
	if !flowRes.OK || !strings.Contains(flowRes.Output, "consume_param") || !strings.Contains(flowRes.Output, "non_write_accessors") {
		t.Fatalf("get_struct_flows failed: %+v", flowRes)
	}
}

func writeTopologyNavFixture(t *testing.T, topo artifacts.BoundaryTopology, symbols []artifacts.SymbolID) string {
	t.Helper()
	run := t.TempDir()
	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1, RunID: "nav-large",
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable, FieldAccesses: artifacts.CapabilityPartial},
	}
	for _, id := range symbols {
		facts.Capsules = append(facts.Capsules, artifacts.FunctionCapsule{SymbolID: id})
	}
	pm := artifacts.ProjectMap{
		SchemaVersion: artifacts.SchemaVersionProjectMapV1, RunID: "nav-large",
		Capabilities: facts.Capabilities, SurfacePartitions: topo.SurfacePartitions,
	}
	for _, item := range []struct {
		path string
		data any
	}{
		{runfs.RepoFactsPath(run), facts},
		{runfs.ProjectMapPath(run), pm},
		{runfs.BoundaryTopologyPath(run), topo},
	} {
		if err := runfs.WriteJSON(item.path, item.data); err != nil {
			t.Fatal(err)
		}
	}
	return run
}

func requireTopologyJSON(t *testing.T, result ActionResult, out any) {
	t.Helper()
	if !result.OK || len(result.Output) > observationlimits.MaxBytes || !json.Valid([]byte(result.Output)) {
		t.Fatalf("expected complete bounded JSON: ok=%v bytes=%d error=%s", result.OK, len(result.Output), result.Error)
	}
	if err := json.Unmarshal([]byte(result.Output), out); err != nil {
		t.Fatal(err)
	}
}

func TestTopologyNav_StructFlowsPagesByBytesWithoutLosingFields(t *testing.T) {
	var symbols []artifacts.SymbolID
	for i := 0; i < 40; i++ {
		symbols = append(symbols, artifacts.MakeSymbolID("cpp", "core/long_accessors.c", i+1,
			fmt.Sprintf("access_%03d_%s", i, strings.Repeat("abcdef", 25)), "(void*)"))
	}
	var topo artifacts.BoundaryTopology
	for i := 0; i < 40; i++ {
		topo.StructFieldBridges = append(topo.StructFieldBridges, artifacts.StructFieldBridge{
			Field: fmt.Sprintf("ctx.field_%03d", i), DirectWriters: symbols[:1],
			NonWriteAccessors: symbols[1:], Accessors: symbols, CrossModule: true,
		})
	}
	run := writeTopologyNavFixture(t, topo, symbols)
	args := getStructFlowsArgs{TypeOrField: "ctx", CrossModuleOnly: true}
	seen := map[string]bool{}
	pages := 0
	for {
		raw, _ := json.Marshal(args)
		result := GetStructFlowsHandler{}.Run(context.Background(), ActionRequest{RunDir: run, Args: raw})
		var page struct {
			MatchedCount int                 `json:"matched_count"`
			TotalPages   int                 `json:"total_pages"`
			Bridges      []bridgeDisplay     `json:"bridges"`
			Truncated    bool                `json:"truncated"`
			NextCursor   *getStructFlowsArgs `json:"next_cursor"`
		}
		requireTopologyJSON(t, result, &page)
		pages++
		if page.MatchedCount != 40 || page.Truncated || result.Truncated {
			t.Fatalf("byte pagination should retain complete individual bridges: %+v", page)
		}
		for _, br := range page.Bridges {
			if seen[br.Field] || len(br.Accessors) != len(symbols) {
				t.Fatalf("duplicate or shortened field %s", br.Field)
			}
			seen[br.Field] = true
		}
		if page.NextCursor == nil {
			if pages != page.TotalPages {
				t.Fatalf("lost final cursor: read %d/%d pages", pages, page.TotalPages)
			}
			break
		}
		if page.NextCursor.Page != args.Page+1 || page.NextCursor.TypeOrField != args.TypeOrField || !page.NextCursor.CrossModuleOnly || pages > 40 {
			t.Fatalf("cursor lost filter or failed to progress: %+v", page.NextCursor)
		}
		args = *page.NextCursor
	}
	if len(seen) != 40 || pages <= 3 {
		t.Fatalf("expected byte-driven pages reaching all 40 fields, got %d fields in %d pages", len(seen), pages)
	}
}

func TestTopologyNav_OversizedBridgeSummaryRetainsRequestedSymbol(t *testing.T) {
	var symbols []artifacts.SymbolID
	for i := 0; i < 600; i++ {
		symbols = append(symbols, artifacts.MakeSymbolID("cpp", "core/consumers.c", i+1,
			fmt.Sprintf("consumer_%03d_%s", i, strings.Repeat("abcdef", 16)), "(void*)"))
	}
	topo := artifacts.BoundaryTopology{StructFieldBridges: []artifacts.StructFieldBridge{{
		Field: "ctx.state", DirectWriters: symbols[:1], NonWriteAccessors: symbols[1:], Accessors: symbols, CrossModule: true,
	}}}
	run := writeTopologyNavFixture(t, topo, symbols)
	for _, symbol := range []artifacts.SymbolID{"", symbols[len(symbols)-1]} {
		args := getStructFlowsArgs{TypeOrField: "ctx.state", CrossModuleOnly: true, SymbolID: string(symbol)}
		raw, _ := json.Marshal(args)
		result := GetStructFlowsHandler{}.Run(context.Background(), ActionRequest{RunDir: run, Args: raw})
		var page struct {
			Bridges    []bridgeDisplay     `json:"bridges"`
			Truncated  bool                `json:"truncated"`
			NextCursor *getStructFlowsArgs `json:"next_cursor"`
		}
		requireTopologyJSON(t, result, &page)
		if !result.Truncated || !page.Truncated || len(page.Bridges) != 1 || page.NextCursor != nil {
			t.Fatalf("expected explicit summary of one oversized bridge: %+v", page)
		}
		br := page.Bridges[0]
		if br.DisplaySummary == nil || br.DisplaySummary.Accessors != 600 || br.DisplaySummary.NonWriteAccessors != 599 || br.DisplaySummary.DirectWriters != 1 {
			t.Fatalf("summary lost original list counts: %+v", br.DisplaySummary)
		}
		if symbol != "" && (!topologyContainsSymbol(br.Accessors, symbol) || !topologyContainsSymbol(br.NonWriteAccessors, symbol) || topologyContainsSymbol(br.DirectWriters, symbol)) {
			t.Fatalf("summary omitted requested definition or invented a writer role: %+v", br)
		}
	}
}

func TestTopologyNav_OversizedClosureDoesNotHideLaterPages(t *testing.T) {
	var topo artifacts.BoundaryTopology
	var symbols []artifacts.SymbolID
	var fields []string
	for i := 0; i < 80; i++ {
		fields = append(fields, fmt.Sprintf("ctx.field_%03d_%s", i, strings.Repeat("界", 60)))
	}
	for i := 0; i < 18; i++ {
		id := artifacts.MakeSymbolID("cpp", "core/entry.c", i+1, fmt.Sprintf("entry_%03d", i), "(void*)")
		symbols = append(symbols, id)
		closure := artifacts.EntryClosure{
			RootSymbolID: id, RootName: fmt.Sprintf("entry_%03d", i), RootPath: "core/entry.c", RootModule: "core",
			RootStartLine: i + 1, RootEndLine: i + 1, Signals: []string{artifacts.EntrySignalGlobalFunctionPointerInitializer},
		}
		if i == 0 {
			closure.DirectFieldWrites, closure.NonWriteFieldAccesses, closure.FieldAccesses = fields, fields, fields
			for j := 0; j < 24; j++ {
				closure.Members = append(closure.Members, artifacts.ClosureMember{
					SymbolID: id, Name: "helper", Path: "core/entry.c", DirectFieldWrites: fields,
					NonWriteFieldAccesses: fields, FieldAccesses: fields,
				})
			}
		}
		topo.EntryClosures = append(topo.EntryClosures, closure)
	}
	topo.SurfacePartitions = []artifacts.SurfacePartition{{
		Bucket: artifacts.SurfaceBucketDispatchTables, RootSymbolIDs: symbols, ClosureCount: len(symbols), ModuleCount: 1,
	}}
	// A display summary must not mutate shared member structs in the original.
	before, _ := json.Marshal(topo.EntryClosures[0])
	_ = summarizeClosure(closureDisplay{EntryClosure: topo.EntryClosures[0]}, 4)
	after, _ := json.Marshal(topo.EntryClosures[0])
	if string(before) != string(after) {
		t.Fatal("display summarization changed original closure facts")
	}
	run := writeTopologyNavFixture(t, topo, symbols)
	args := listBoundaryClosuresArgs{Bucket: artifacts.SurfaceBucketDispatchTables, Module: "core"}
	seen := map[artifacts.SymbolID]bool{}
	sawSummary := false
	for count := 0; ; count++ {
		raw, _ := json.Marshal(args)
		result := ListBoundaryClosuresHandler{}.Run(context.Background(), ActionRequest{RunDir: run, Args: raw})
		var page struct {
			Closures          []closureDisplay             `json:"closures"`
			SurfacePartitions []artifacts.SurfacePartition `json:"surface_partitions"`
			NextCursor        *listBoundaryClosuresArgs    `json:"next_cursor"`
		}
		requireTopologyJSON(t, result, &page)
		for _, part := range page.SurfacePartitions {
			if len(part.RootSymbolIDs) != 0 {
				t.Fatal("page envelope repeated full partition membership")
			}
		}
		for _, closure := range page.Closures {
			if seen[closure.RootSymbolID] {
				t.Fatalf("duplicate closure %s", closure.RootSymbolID)
			}
			seen[closure.RootSymbolID] = true
			if closure.RootSymbolID == symbols[0] {
				sawSummary = true
				if !result.Truncated || closure.DisplaySummary == nil || !closure.MembersTruncated || closure.DisplaySummary.StoredMembers != 24 || closure.DisplaySummary.FieldAccesses != 80 {
					t.Fatalf("oversized closure has no honest count summary: %+v", closure)
				}
			}
		}
		if page.NextCursor == nil {
			break
		}
		if page.NextCursor.Page != args.Page+1 || page.NextCursor.Bucket != args.Bucket || page.NextCursor.Module != args.Module || count > 18 {
			t.Fatalf("closure cursor lost filters or failed to progress: %+v", page.NextCursor)
		}
		args = *page.NextCursor
	}
	if len(seen) != 18 || !sawSummary {
		t.Fatalf("oversized closure hid later entries: %d seen, summary=%v", len(seen), sawSummary)
	}
}
