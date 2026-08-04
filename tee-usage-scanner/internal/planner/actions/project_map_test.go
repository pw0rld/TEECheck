package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func capsuleFor(file, module, name string, line int) artifacts.FunctionCapsule {
	return artifacts.FunctionCapsule{
		SymbolID: artifacts.MakeSymbolID("cpp", file, line, name, "()"),
		Name:     name, Module: module, File: file, Line: line,
	}
}

// browseRun writes an index and a map, and returns the run dir.
func browseRun(t *testing.T, facts artifacts.RepoFacts, m artifacts.ProjectMap, pages map[string][]artifacts.FunctionCapsule) string {
	t.Helper()
	runDir := t.TempDir()
	facts.SchemaVersion = artifacts.SchemaVersionRepoFactsV1
	facts.RunID = "run-browse"
	m.SchemaVersion = artifacts.SchemaVersionProjectMapV1
	m.RunID = "run-browse"
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(runDir), m); err != nil {
		t.Fatal(err)
	}
	for rel, page := range pages {
		full := filepath.Join(runDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := runfs.WriteJSON(full, page); err != nil {
			t.Fatal(err)
		}
	}
	return runDir
}

func fullCaps() artifacts.IndexCapabilities {
	return artifacts.IndexCapabilities{
		Symbols: artifacts.CapabilityAvailable, DirectCalls: artifacts.CapabilityPartial,
		FieldAccesses: artifacts.CapabilityPartial, BuildReachability: artifacts.CapabilityUnavailable,
	}
}

// probeIndex is a small but complete index: two same-named statics, a
// producer and a consumer, one page per module.
func probeIndex(t *testing.T) string {
	t.Helper()
	loader := capsuleFor("core/crypto/signed_hdr.c", "core/crypto", "shdr_load_pub_key", 262)
	loader.DirectFieldWrites = []string{"shdr_pub_key.max_depth"}
	loader.FieldAccesses = []string{"shdr_pub_key.max_depth", "shdr_subkey.uuid"}
	consumer := capsuleFor("core/kernel/ree_fs_ta.c", "core/kernel", "ree_fs_ta_open", 298)
	consumer.Calls = []artifacts.SymbolID{loader.SymbolID}
	loader.CalledBy = []artifacts.SymbolID{consumer.SymbolID}
	helperA := capsuleFor("core/crypto/a.c", "core/crypto", "helper", 10)
	helperB := capsuleFor("core/kernel/b.c", "core/kernel", "helper", 20)

	facts := artifacts.RepoFacts{
		Capabilities: fullCaps(),
		Capsules:     []artifacts.FunctionCapsule{loader, consumer, helperA, helperB},
		CallEdges: []artifacts.CallEdge{{
			CallerID: consumer.SymbolID, CalleeID: loader.SymbolID,
			File: "core/kernel/ree_fs_ta.c", Line: 314, Resolution: artifacts.ResolutionDirect,
		}},
		TotalCallSites: 42317, ResolvedCallSites: 40765,
		UnresolvedCallSiteCount: 1552, ExternalCallSites: 3458, AmbiguousCallSites: 1883,
	}
	m := artifacts.ProjectMap{
		Capabilities: fullCaps(),
		Repository: artifacts.RepositoryCard{
			DocumentedPurpose: "OP-TEE Trusted OS", Languages: []string{"cpp"},
			BuildTargets: []string{"make"}, FileCount: 3291,
		},
		Modules: []artifacts.ModuleCard{
			{Path: "core/crypto", FileCount: 40, FunctionCount: 2, CalledByModules: []string{"core/kernel"}},
			{Path: "lib/libmbedtls", FileCount: 898, FunctionCount: 4000},
		},
		FunctionPages: []artifacts.FunctionCardPageRef{
			{Module: "core/crypto", Page: 0, Count: 2, Path: "01_context/function_cards/core-crypto-aaaa/0.json"},
			{Module: "core/crypto", Page: 1, Count: 1, Path: "01_context/function_cards/core-crypto-aaaa/1.json"},
		},
	}
	return browseRun(t, facts, m, map[string][]artifacts.FunctionCapsule{
		"01_context/function_cards/core-crypto-aaaa/0.json": {loader, helperA},
		"01_context/function_cards/core-crypto-aaaa/1.json": {consumer},
	})
}

func run(t *testing.T, h actions.Handler, runDir, args string) actions.ActionResult {
	t.Helper()
	return h.Run(context.Background(), actions.ActionRequest{
		Name: h.Name(), RunDir: runDir, Args: json.RawMessage(args),
	})
}

// The ORIENT state needs an observable event, and the gate reads it from the
// action name. Without this action RepositoryCardRead could never become
// true and the reconnaissance gate could never be satisfied.
func TestGetRepositoryCard_ReportsThePurposeAndTheModuleSizes(t *testing.T) {
	res := run(t, actions.GetRepositoryCardHandler{}, probeIndex(t), `{}`)
	if !res.OK {
		t.Fatalf("get_repository_card failed: %s", res.Error)
	}
	for _, want := range []string{"OP-TEE Trusted OS", "make", "3291"} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("output missing %q:\n%s", want, res.Output)
		}
	}
}

// The number that tells first-party code from vendored dependencies. Without
// it every consumer treated lib/libmbedtls as project code.
func TestListModules_ReportsSizeSoVendoredCodeIsVisible(t *testing.T) {
	res := run(t, actions.ListModulesHandler{}, probeIndex(t), `{}`)
	if !res.OK {
		t.Fatalf("list_modules failed: %s", res.Error)
	}
	if !strings.Contains(res.Output, "lib/libmbedtls") || !strings.Contains(res.Output, "898") {
		t.Errorf("output must carry per-module size:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "core/kernel") {
		t.Errorf("module dependency edges must be visible:\n%s", res.Output)
	}
}

// Paging is the whole point: the full capsule set is megabytes.
func TestListFunctions_PagesAndSaysWhereItIs(t *testing.T) {
	runDir := probeIndex(t)
	res := run(t, actions.ListFunctionsHandler{}, runDir, `{"module":"core/crypto","page":0}`)
	if !res.OK {
		t.Fatalf("list_functions failed: %s", res.Error)
	}
	if !strings.Contains(res.Output, "shdr_load_pub_key") {
		t.Errorf("page 0 must hold its capsules:\n%s", res.Output)
	}
	// The model must be able to ask for the next page without guessing.
	if !strings.Contains(res.Output, "next_cursor") {
		t.Errorf("output must name the next cursor:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "page 0 of 2") {
		t.Errorf("output must say which page of how many:\n%s", res.Output)
	}

	last := run(t, actions.ListFunctionsHandler{}, runDir, `{"module":"core/crypto","page":1}`)
	if strings.Contains(last.Output, "next_cursor") {
		t.Errorf("the last page must not advertise a next cursor:\n%s", last.Output)
	}
}

// A module the index has no pages for is not a module with no functions.
func TestListFunctions_UnknownModuleCarriesItsScope(t *testing.T) {
	res := run(t, actions.ListFunctionsHandler{}, probeIndex(t), `{"module":"does/not/exist"}`)
	if res.OK {
		t.Fatal("an unknown module must not report success")
	}
	if !strings.Contains(res.Error, "not_found_in_indexed_repository") {
		t.Errorf("the refusal must use the negative-evidence ladder: %s", res.Error)
	}
}

// The Planner knows names, not ids. find_symbols must hand back every
// candidate rather than choosing one — choosing is the identity guess
// SymbolID exists to prevent.
func TestFindSymbols_ReturnsEveryCandidateAndPicksNone(t *testing.T) {
	res := run(t, actions.FindSymbolsHandler{}, probeIndex(t), `{"name":"helper"}`)
	if !res.OK {
		t.Fatalf("find_symbols failed: %s", res.Error)
	}
	if !strings.Contains(res.Output, "core/crypto/a.c") || !strings.Contains(res.Output, "core/kernel/b.c") {
		t.Errorf("both same-named definitions must be offered:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "2 match") {
		t.Errorf("the count must be stated so the model knows it is choosing:\n%s", res.Output)
	}
}

func TestGetFunctionCard_ReturnsTheCapsuleAndItsScopes(t *testing.T) {
	runDir := probeIndex(t)
	id := artifacts.MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "shdr_load_pub_key", "()")
	res := run(t, actions.GetFunctionCardHandler{}, runDir, `{"symbol_id":"`+string(id)+`"}`)
	if !res.OK {
		t.Fatalf("get_function_card failed: %s", res.Error)
	}
	if !strings.Contains(res.Output, "shdr_pub_key.max_depth") {
		t.Errorf("the card must carry its field facts:\n%s", res.Output)
	}
	// The limits travel with the answer, not in a footnote somewhere else.
	for _, want := range []string{"direct_assignment_only", "direct_resolved_calls_only"} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("the card must state %q beside its lists:\n%s", want, res.Output)
		}
	}
}

// A symbol the index does not hold is not a symbol that does not exist.
func TestGetFunctionCard_UnknownIDCarriesItsScope(t *testing.T) {
	res := run(t, actions.GetFunctionCardHandler{}, probeIndex(t), `{"symbol_id":"cpp:x.c:1:nope()"}`)
	if res.OK {
		t.Fatal("an unknown id must not report success")
	}
	if !strings.Contains(res.Error, "not_found_in_indexed_repository") {
		t.Errorf("the refusal must use the negative-evidence ladder: %s", res.Error)
	}
	if !strings.Contains(res.Error, "ripgrep") {
		t.Errorf("the refusal must say what would still find it: %s", res.Error)
	}
}

// "No callers" is only readable next to the reasons a caller can be missing.
// Without them a consumer reads an empty list as evidence of unreachability,
// which is exactly the inference BUG-002 turned into a wrong verdict.
func TestGetCallers_StatesEveryReasonACallerCanBeMissing(t *testing.T) {
	runDir := probeIndex(t)
	id := artifacts.MakeSymbolID("cpp", "core/crypto/a.c", 10, "helper", "()")
	res := run(t, actions.GetCallersHandler{}, runDir, `{"symbol_id":"`+string(id)+`"}`)
	if !res.OK {
		t.Fatalf("get_callers failed: %s", res.Error)
	}
	for _, want := range []string{
		"direct_resolved_calls_only",
		"1552", // unresolved call sites
		"3458", // external
		"1883", // ambiguous
	} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("an empty caller list must carry %q:\n%s", want, res.Output)
		}
	}
	if strings.Contains(strings.ToLower(res.Output), "never called") {
		t.Error("the answer must not assert unreachability")
	}
}

// With no index there is nothing to browse, and every handler has to say so
// rather than return an empty result that reads as a fact about the code.
func TestBrowsingActions_UnavailableIndexIsDistinctFromEmpty(t *testing.T) {
	none := artifacts.IndexCapabilities{
		Symbols: artifacts.CapabilityUnavailable, DirectCalls: artifacts.CapabilityUnavailable,
		FieldAccesses: artifacts.CapabilityUnavailable, BuildReachability: artifacts.CapabilityUnavailable,
	}
	runDir := browseRun(t,
		artifacts.RepoFacts{Capabilities: none, IndexNote: "codeql database: extractor found no compilable source"},
		artifacts.ProjectMap{Capabilities: none}, nil)

	for _, tc := range []struct {
		h    actions.Handler
		args string
	}{
		{actions.ListModulesHandler{}, `{}`},
		{actions.ListFunctionsHandler{}, `{"module":"core"}`},
		{actions.FindSymbolsHandler{}, `{"name":"helper"}`},
		{actions.GetFunctionCardHandler{}, `{"symbol_id":"cpp:a.c:1:f()"}`},
		{actions.GetCallersHandler{}, `{"symbol_id":"cpp:a.c:1:f()"}`},
	} {
		res := run(t, tc.h, runDir, tc.args)
		body := strings.ToLower(res.Output + " " + res.Error)
		if !strings.Contains(body, "unavailable") {
			t.Errorf("%s must say the index is unavailable, got output=%q error=%q",
				tc.h.Name(), res.Output, res.Error)
		}
		if !strings.Contains(body, "extractor found no compilable source") {
			t.Errorf("%s must carry the index's own note: %q", tc.h.Name(), body)
		}
	}
}

// One cap, shared. A handler with its own number is how a page built to one
// budget arrives cut by another, looking complete.
func TestBrowsingActions_RespectTheSharedObservationCap(t *testing.T) {
	big := strings.Repeat("z", observationlimits.MaxBytes)
	var caps []artifacts.FunctionCapsule
	for i := 0; i < 40; i++ {
		c := capsuleFor("core/crypto/x.c", "core/crypto", "fn", i+1)
		c.FieldAccesses = []string{big}
		caps = append(caps, c)
	}
	facts := artifacts.RepoFacts{Capabilities: fullCaps(), Capsules: caps}
	m := artifacts.ProjectMap{
		Capabilities: fullCaps(),
		FunctionPages: []artifacts.FunctionCardPageRef{
			{Module: "core/crypto", Page: 0, Count: len(caps), Path: "01_context/function_cards/c/0.json"},
		},
	}
	runDir := browseRun(t, facts, m, map[string][]artifacts.FunctionCapsule{
		"01_context/function_cards/c/0.json": caps,
	})

	res := run(t, actions.ListFunctionsHandler{}, runDir, `{"module":"core/crypto","page":0}`)
	if len(res.Output) > observationlimits.MaxBytes {
		t.Errorf("output is %d bytes, over the %d cap", len(res.Output), observationlimits.MaxBytes)
	}
	if !res.Truncated {
		t.Error("an output that was cut must say so — a silent cut reads as complete")
	}
	if !strings.Contains(res.Output, "truncated") {
		t.Errorf("the cut must be visible in the text the model reads:\n%s", res.Output[max(0, len(res.Output)-200):])
	}
}

// The other half of the same constraint, and the half that catches the
// failure that actually happened: a page built to the shared budget must
// arrive whole. A handler using a smaller number of its own cuts a page that
// was sized to fit, and the model reads a prefix that looks complete —
// exactly what the planner's 4000-character excerpt did to a 32 KiB page.
func TestBrowsingActions_APageBuiltToTheBudgetArrivesWhole(t *testing.T) {
	// Sized so the rendered page lands just under the shared cap.
	var caps []artifacts.FunctionCapsule
	for i := 0; i < 60; i++ {
		c := capsuleFor("core/crypto/x.c", "core/crypto", "fn", i+1)
		c.FieldAccesses = []string{strings.Repeat("f", 200)}
		caps = append(caps, c)
	}
	last := capsuleFor("core/crypto/x.c", "core/crypto", "THE_LAST_ONE", 9999)
	caps = append(caps, last)

	facts := artifacts.RepoFacts{Capabilities: fullCaps(), Capsules: caps}
	m := artifacts.ProjectMap{
		Capabilities: fullCaps(),
		FunctionPages: []artifacts.FunctionCardPageRef{
			{Module: "core/crypto", Page: 0, Count: len(caps), Path: "01_context/function_cards/c/0.json"},
		},
	}
	runDir := browseRun(t, facts, m, map[string][]artifacts.FunctionCapsule{
		"01_context/function_cards/c/0.json": caps,
	})

	res := run(t, actions.ListFunctionsHandler{}, runDir, `{"module":"core/crypto","page":0}`)
	if !res.OK {
		t.Fatalf("list_functions failed: %s", res.Error)
	}
	if res.Truncated {
		t.Fatalf("a page under the %d-byte budget was cut at %d bytes — the handler is using a limit of its own",
			observationlimits.MaxBytes, len(res.Output))
	}
	if !strings.Contains(res.Output, "THE_LAST_ONE") {
		t.Error("the last capsule of a page that fits must survive the trip")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Every registered action must be documented in the prompt's schema map, or
// the model guesses at parameter names — the failure that made the planner
// pass include_patterns to a handler wanting globs.
func TestBrowsingActions_AreAdvertisedWithTheirArgs(t *testing.T) {
	reg := actions.NewDefaultRegistryWithNav()
	registered := map[string]bool{}
	for _, n := range reg.Names() {
		registered[n] = true
	}
	prompt := planner.BuildSystemPrompt(reg.Names(), "", planner.PriorKnowledge{}, planner.PhaseInvestigation)
	for _, name := range []string{
		"get_repository_card", "list_modules", "list_functions",
		"find_symbols", "get_function_card", "get_callers",
	} {
		if !registered[name] {
			t.Errorf("%s is not registered", name)
		}
		if !strings.Contains(prompt, name) {
			t.Errorf("%s is not advertised in the system prompt", name)
		}
		// The fallback schema. An action advertised with it is one the model
		// will guess the parameter names for — the failure that had the
		// planner passing include_patterns to a handler wanting globs.
		if strings.Contains(prompt, name+"  args={...}") {
			t.Errorf("%s is advertised with no arg schema — the model will guess", name)
		}
	}
}

// A SymbolID is lang:file:line:name(signature), and the signature is part
// of it. On the first real run against OP-TEE the model opened a card with
// the full id and then asked get_callers about the same function with
// everything after the name removed. Both refusals were correct and neither
// said what was wrong, so the run finished with zero relation queries — the
// one reconnaissance requirement it never met.
func TestBrowsingActions_ADroppedSignatureIsNamedAsSuch(t *testing.T) {
	runDir := probeIndex(t)

	full := string(artifacts.MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "shdr_load_pub_key", "()"))
	truncated := "cpp:core/crypto/signed_hdr.c:262:shdr_load_pub_key"
	if full == truncated {
		t.Fatal("the fixture must build an id whose signature can be dropped")
	}

	if res := run(t, actions.GetFunctionCardHandler{}, runDir, `{"symbol_id":"`+full+`"}`); !res.OK {
		t.Fatalf("the fixture must hold %s: %s", full, res.Error)
	}

	for _, h := range []actions.Handler{actions.GetFunctionCardHandler{}, actions.GetCallersHandler{}} {
		res := run(t, h, runDir, `{"symbol_id":"`+truncated+`"}`)
		if res.OK {
			t.Fatalf("%s accepted an id with no signature", h.Name())
		}
		if !strings.Contains(res.Error, full) {
			t.Errorf("%s did not name the id that would have worked:\n%s", h.Name(), res.Error)
		}
		if !strings.Contains(res.Error, "signature") {
			t.Errorf("%s did not say what was missing:\n%s", h.Name(), res.Error)
		}
	}
}

// Naming near matches is not choosing between them, and an id that matches
// nothing must not be reported as a dropped signature — that would send the
// model looking for a suffix that does not exist.
func TestBrowsingActions_AnIdThatMatchesNothingSaysSoDifferently(t *testing.T) {
	res := run(t, actions.GetFunctionCardHandler{}, probeIndex(t),
		`{"symbol_id":"cpp:core/nowhere.c:1:absent"}`)
	if res.OK {
		t.Fatal("an id matching nothing must be refused")
	}
	if strings.Contains(res.Error, "signature") {
		t.Errorf("an id with no near match must not be reported as a dropped signature:\n%s", res.Error)
	}
	if !strings.Contains(res.Error, "not_found_in_indexed_repository") {
		t.Errorf("the refusal must carry a §7 ladder value:\n%s", res.Error)
	}
	if !strings.Contains(res.Error, "find_symbols") {
		t.Errorf("the refusal must name what would still find it:\n%s", res.Error)
	}
}
