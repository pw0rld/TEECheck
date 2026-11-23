package topology

import (
	"fmt"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func TestBuild_ThreeHopClosureAndStructFieldBridges(t *testing.T) {
	entryID := artifacts.MakeSymbolID("cpp", "core/tee/tee_entry.c", 10, "tee_entry_std", "(uint32_t)")
	hop1ID := artifacts.MakeSymbolID("cpp", "core/tee/tee_entry.c", 40, "entry_invoke_command", "(void*)")
	hop2ID := artifacts.MakeSymbolID("cpp", "core/tee/tee_entry.c", 80, "copy_in_params", "(void*)")
	hop3ID := artifacts.MakeSymbolID("cpp", "core/tee/tee_entry.c", 120, "set_rmem_param", "(void*)")
	hop4ID := artifacts.MakeSymbolID("cpp", "core/tee/tee_entry.c", 160, "too_deep_helper", "(void)")
	consumerID := artifacts.MakeSymbolID("cpp", "core/mm/mobj.c", 55, "mobj_reg_shm_inc_map", "(void*)")

	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1,
		RunID:         "topo-test",
		Symbols: []artifacts.Symbol{
			{SymbolID: entryID, Name: "tee_entry_std", File: "core/tee/tee_entry.c", StartLine: 10, Module: "core/tee"},
			{SymbolID: hop1ID, Name: "entry_invoke_command", File: "core/tee/tee_entry.c", StartLine: 40, Module: "core/tee"},
			{SymbolID: hop2ID, Name: "copy_in_params", File: "core/tee/tee_entry.c", StartLine: 80, Module: "core/tee"},
			{SymbolID: hop3ID, Name: "set_rmem_param", File: "core/tee/tee_entry.c", StartLine: 120, Module: "core/tee"},
			{SymbolID: hop4ID, Name: "too_deep_helper", File: "core/tee/tee_entry.c", StartLine: 160, Module: "core/tee"},
			{SymbolID: consumerID, Name: "mobj_reg_shm_inc_map", File: "core/mm/mobj.c", StartLine: 55, Module: "core/mm"},
		},
		Capsules: []artifacts.FunctionCapsule{
			{SymbolID: entryID, Name: "tee_entry_std", Module: "core/tee", File: "core/tee/tee_entry.c", Line: 10, Calls: []artifacts.SymbolID{hop1ID}},
			{SymbolID: hop1ID, Name: "entry_invoke_command", Module: "core/tee", File: "core/tee/tee_entry.c", Line: 40, CalledBy: []artifacts.SymbolID{entryID}, Calls: []artifacts.SymbolID{hop2ID}},
			{SymbolID: hop2ID, Name: "copy_in_params", Module: "core/tee", File: "core/tee/tee_entry.c", Line: 80, CalledBy: []artifacts.SymbolID{hop1ID}, Calls: []artifacts.SymbolID{hop3ID}},
			{
				SymbolID:          hop3ID,
				Name:              "set_rmem_param",
				Module:            "core/tee",
				File:              "core/tee/tee_entry.c",
				Line:              120,
				CalledBy:          []artifacts.SymbolID{hop2ID},
				Calls:             []artifacts.SymbolID{hop4ID},
				FieldAccesses:     []string{"param_mem.size", "param_mem.offs"},
				DirectFieldWrites: []string{"param_mem.size", "param_mem.offs"},
			},
			{SymbolID: hop4ID, Name: "too_deep_helper", Module: "core/tee", File: "core/tee/tee_entry.c", Line: 160, CalledBy: []artifacts.SymbolID{hop3ID}},
			{
				SymbolID:      consumerID,
				Name:          "mobj_reg_shm_inc_map",
				Module:        "core/mm",
				File:          "core/mm/mobj.c",
				Line:          55,
				FieldAccesses: []string{"param_mem.size"},
			},
		},
		CallEdges: []artifacts.CallEdge{
			{CallerID: entryID, CalleeID: hop1ID, File: "core/tee/tee_entry.c", Line: 20, Resolution: artifacts.ResolutionDirect},
			{CallerID: hop1ID, CalleeID: hop2ID, File: "core/tee/tee_entry.c", Line: 55, Resolution: artifacts.ResolutionDirect},
			{CallerID: hop2ID, CalleeID: hop3ID, File: "core/tee/tee_entry.c", Line: 95, Resolution: artifacts.ResolutionDirect},
			{CallerID: hop3ID, CalleeID: hop4ID, File: "core/tee/tee_entry.c", Line: 130, Resolution: artifacts.ResolutionDirect},
		},
	}
	entries := []artifacts.EntrySurface{{
		SymbolID:  entryID,
		Name:      "tee_entry_std",
		Path:      "core/tee/tee_entry.c",
		Module:    "core/tee",
		StartLine: 10,
		EndLine:   35,
		Signals:   []string{artifacts.EntrySignalExternalLinkage, artifacts.EntrySignalNoResolvedInternalCallers},
	}}

	topo := Build("topo-test", artifacts.ScannedScope{}, facts, entries)
	if len(topo.EntryClosures) != 1 {
		t.Fatalf("EntryClosures = %d, want 1", len(topo.EntryClosures))
	}
	closure := topo.EntryClosures[0]
	if closure.MaxDepth != 3 || len(closure.Members) != 4 {
		t.Fatalf("closure depth=%d members=%d, want depth=3 members=4 (hop4 excluded)", closure.MaxDepth, len(closure.Members))
	}
	if len(topo.StructFieldBridges) != 1 || topo.StructFieldBridges[0].Field != "param_mem.size" || !topo.StructFieldBridges[0].CrossModule {
		t.Fatalf("StructFieldBridges = %+v, want cross-module bridge on param_mem.size", topo.StructFieldBridges)
	}
	br := topo.StructFieldBridges[0]
	if len(br.DirectWriters) != 1 || br.DirectWriters[0] != hop3ID || len(br.NonWriteAccessors) != 1 || br.NonWriteAccessors[0] != consumerID {
		t.Fatalf("unexpected bridge roles: %+v", br)
	}
}

func TestBuildStructFieldBridges_SameModulePureWritersExcluded(t *testing.T) {
	w1 := artifacts.MakeSymbolID("cpp", "core/a.c", 10, "init_a", "(void)")
	w2 := artifacts.MakeSymbolID("cpp", "core/a.c", 20, "reset_a", "(void)")
	bridges := BuildStructFieldBridges([]artifacts.FunctionCapsule{
		{SymbolID: w1, Name: "init_a", Module: "core", File: "core/a.c", Line: 10, FieldAccesses: []string{"ctx.state"}, DirectFieldWrites: []string{"ctx.state"}},
		{SymbolID: w2, Name: "reset_a", Module: "core", File: "core/a.c", Line: 20, FieldAccesses: []string{"ctx.state"}, DirectFieldWrites: []string{"ctx.state"}},
	})
	if len(bridges) != 0 {
		t.Fatalf("two pure writers in the same module should not form a bridge: %+v", bridges)
	}
}

func TestBuild_SharedStateLifecyclesPreservesMixedReadAndWriteHelpersInSameClosure(t *testing.T) {
	entry1 := artifacts.MakeSymbolID("cpp", "core/svc.c", 10, "entry_open", "(void)")
	writeHelper := artifacts.MakeSymbolID("cpp", "core/svc.c", 30, "set_state", "(void)")
	readHelper := artifacts.MakeSymbolID("cpp", "core/svc.c", 50, "check_state", "(void)")
	entry2 := artifacts.MakeSymbolID("cpp", "core/svc.c", 70, "entry_Step", "(void)")

	facts := artifacts.RepoFacts{
		SchemaVersion: artifacts.SchemaVersionRepoFactsV1,
		RunID:         "shared-state-test",
		Symbols: []artifacts.Symbol{
			{SymbolID: entry1, Name: "entry_open", File: "core/svc.c", StartLine: 10, Module: "core"},
			{SymbolID: writeHelper, Name: "set_state", File: "core/svc.c", StartLine: 30, Module: "core"},
			{SymbolID: readHelper, Name: "check_state", File: "core/svc.c", StartLine: 50, Module: "core"},
			{SymbolID: entry2, Name: "entry_Step", File: "core/svc.c", StartLine: 70, Module: "core"},
		},
		Capsules: []artifacts.FunctionCapsule{
			{SymbolID: entry1, Name: "entry_open", Module: "core", File: "core/svc.c", Line: 10, Calls: []artifacts.SymbolID{writeHelper, readHelper}},
			{SymbolID: writeHelper, Name: "set_state", Module: "core", File: "core/svc.c", Line: 30, CalledBy: []artifacts.SymbolID{entry1}, FieldAccesses: []string{"sess.state"}, DirectFieldWrites: []string{"sess.state"}},
			{SymbolID: readHelper, Name: "check_state", Module: "core", File: "core/svc.c", Line: 50, CalledBy: []artifacts.SymbolID{entry1}, FieldAccesses: []string{"sess.state"}},
			{SymbolID: entry2, Name: "entry_Step", Module: "core", File: "core/svc.c", Line: 70, FieldAccesses: []string{"sess.state"}, DirectFieldWrites: []string{"sess.state"}},
		},
		CallEdges: []artifacts.CallEdge{
			{CallerID: entry1, CalleeID: writeHelper, File: "core/svc.c", Line: 15, Resolution: artifacts.ResolutionDirect},
			{CallerID: entry1, CalleeID: readHelper, File: "core/svc.c", Line: 16, Resolution: artifacts.ResolutionDirect},
		},
	}
	entries := []artifacts.EntrySurface{
		{SymbolID: entry1, Name: "entry_open", Path: "core/svc.c", Module: "core", StartLine: 10, EndLine: 20, Signals: []string{artifacts.EntrySignalExternalLinkage}},
		{SymbolID: entry2, Name: "entry_Step", Path: "core/svc.c", Module: "core", StartLine: 70, EndLine: 80, Signals: []string{artifacts.EntrySignalExternalLinkage}},
	}

	topo := Build("shared-state-test", artifacts.ScannedScope{}, facts, entries)
	if len(topo.EntryClosures[0].NonWriteFieldAccesses) != 1 || topo.EntryClosures[0].NonWriteFieldAccesses[0] != "sess.state" {
		t.Fatalf("closure 0 lost NonWriteFieldAccesses when calling both write and read helpers: %+v", topo.EntryClosures[0])
	}
	var sharedPart artifacts.SurfacePartition
	for _, p := range topo.SurfacePartitions {
		if p.Bucket == artifacts.SurfaceBucketSharedStateLifecycle {
			sharedPart = p
		}
	}
	if sharedPart.ClosureCount != 2 {
		t.Fatalf("shared_state_lifecycles count = %d, want 2: %+v", sharedPart.ClosureCount, topo.SurfacePartitions)
	}
}

func TestDiversifyClosures_StrictPerFileCapEvenWithinSameModule(t *testing.T) {
	var input []artifacts.EntryClosure
	for i := 0; i < 6; i++ {
		input = append(input, artifacts.EntryClosure{
			RootSymbolID:  artifacts.SymbolID(fmt.Sprintf("cpp:core/tee/fileA.c:%d:fnA_%d()", i+1, i)),
			RootName:      fmt.Sprintf("fnA_%d", i),
			RootPath:      "core/tee/fileA.c",
			RootModule:    "core/tee",
			RootStartLine: i + 1,
		})
	}
	for i := 0; i < 4; i++ {
		input = append(input, artifacts.EntryClosure{
			RootSymbolID:  artifacts.SymbolID(fmt.Sprintf("cpp:core/tee/fileB.c:%d:fnB_%d()", i+1, i)),
			RootName:      fmt.Sprintf("fnB_%d", i),
			RootPath:      "core/tee/fileB.c",
			RootModule:    "core/tee",
			RootStartLine: i + 1,
		})
	}
	for i := 0; i < 2; i++ {
		input = append(input, artifacts.EntryClosure{
			RootSymbolID:  artifacts.SymbolID(fmt.Sprintf("cpp:core/mm/fileC.c:%d:fnC_%d()", i+1, i)),
			RootName:      fmt.Sprintf("fnC_%d", i),
			RootPath:      "core/mm/fileC.c",
			RootModule:    "core/mm",
			RootStartLine: i + 1,
		})
	}

	got := DiversifyClosures(input, 2)
	if len(got) != len(input) {
		t.Fatalf("len(got)=%d, want %d", len(got), len(input))
	}
	streak := 1
	for i := 1; i < 8; i++ {
		if got[i].RootPath == got[i-1].RootPath {
			streak++
			if streak > 2 {
				t.Fatalf("file %s appeared %d times consecutively at index %d: %+v", got[i].RootPath, streak, i, got[:8])
			}
		} else {
			streak = 1
		}
	}
}

func TestDiversifyClosures_DeprioritizesNestedLibraryDirectories(t *testing.T) {
	modules := []string{
		"core/lib/libtomcrypt", "core/third_party/crypto", "core/vendor/math", "core/external/parser",
		"lib/crypto", "third_party/math", "vendor/parser", "external/compression",
		"core/tee", "core/kernel", "core/library_service", "core/third_party_api",
	}
	var input []artifacts.EntryClosure
	for i, module := range modules {
		closure := artifacts.EntryClosure{
			RootSymbolID: artifacts.SymbolID(module),
			RootModule:   module,
			RootPath:     module + "/entry.c",
		}
		if i < 8 {
			// Even structurally richer library closures should yield the
			// first wave's initial slots to first-party boundary modules.
			closure.Members = make([]artifacts.ClosureMember, 2)
			closure.DirectFieldWrites = []string{"ctx.state"}
		}
		input = append(input, closure)
	}
	got := DiversifyClosures(input, 2)
	if len(got) != len(input) {
		t.Fatalf("lost closures: got %d, want %d", len(got), len(input))
	}
	firstParty := map[string]bool{
		"core/tee": true, "core/kernel": true, "core/library_service": true, "core/third_party_api": true,
	}
	seen := map[artifacts.SymbolID]bool{}
	for i, closure := range got {
		if firstParty[closure.RootModule] != (i < len(firstParty)) {
			t.Fatalf("unexpected boundary/library order at %d: %+v", i, got)
		}
		if seen[closure.RootSymbolID] {
			t.Fatalf("duplicate closure %s", closure.RootSymbolID)
		}
		seen[closure.RootSymbolID] = true
	}
	for i, closure := range input {
		if closure.RootModule != modules[i] || !seen[closure.RootSymbolID] {
			t.Fatalf("original closure changed or disappeared at %d: %+v", i, closure)
		}
	}
}
